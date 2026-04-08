# CredSSP — état complet (post-refacto hyper/openssl)

Document de reprise. Ce qui marche, ce qui bloque, ce qu'on a essayé, et les
pistes restantes.

---

## TL;DR

- **Toute la cryptographie est correcte** (5 bugs trouvés et corrigés, vérifiés
  byte-pour-byte contre `pyspnego` via tests à vecteurs déterministes).
- **Le transport HTTP a été refait** : on ne passe plus par `reqwest`. Une
  seule connexion TCP+TLS persistante via `tokio-rustls` (outer) +
  `openssl` MemBio (inner), HTTP/1.1 raw écrit à la main.
- **L'auth NTLM réussit côté serveur** : event `4624` (Logon Success) +
  ETW capture lsass `STATUS_SUCCESS`, flag `MIC Provided` confirmé.
- **L'ASN.1 TSRequest est byte-identique à pyspnego** (vérifié avec randoms
  forcés CC+RSK+nonce — diff = 96 octets, tous des outputs cryptographiques
  qui dépendent du timestamp serveur dynamique. **Zéro byte structurel
  diffère**.)
- **Le server CredSSP version est `6`** (parsé du Type 2 response) — on est
  bien aligné.
- **ETW server-side capture l'erreur exacte** : juste après NTLM SUCCESS,
  l'event `Microsoft-Windows-WinRM 1294` (Warning, channel Analytic) fire
  avec le message **« Sending HTTP 401 response to the client and disconnect
  the connection after sending the response »**. Le serveur décide
  EXPLICITEMENT de drop la connexion. Action confirmée par le SslDisconnReq
  HttpService event qui suit.
- **Cause exacte = inconnue**. Les events qui fire entre la fin de NTLM et
  le 1294 sont des events de providers sans manifest (`eb7563ce-…`,
  `56149e46-…`, `ddbf5b7e-…` — task GUIDs internes WinRM/CredSSP). Sans
  symboles, impossible de décoder le motif précis du rejet.
- **Hypothèse résiduelle la plus probable** : la couche CredSSP côté serveur
  vérifie notre `pubKeyAuth` après NTLM, et la vérification échoue. Mais
  notre `seal()` est bit-perfect contre pyspnego (test vector), notre
  extraction de SubjectPublicKey est bit-identique entre `x509-cert` et
  notre parser DER manuel, et le magic+nonce+spk respectent MS-CSSP §2.2.2.3.
- **`pywinrm` fonctionne contre la même VM, mêmes creds, mêmes secondes** —
  donc pas un problème d'infra brut. Reste possible : un état serveur
  collant après nos centaines de tentatives ratées (lockout silencieux,
  cache CredSSP foireux). **Reboot Windows non encore effectué.**

---

## Ce qui a été corrigé (5 bugs crypto)

| # | Fichier | Bug | Comment vérifié |
|---|---|---|---|
| 1 | [src/ntlm/mod.rs:111](src/ntlm/mod.rs#L111) (`NtlmSession::seal`) | Ordre RC4 inversé : on chiffrait le checksum **avant** le plaintext. Pyspnego fait `rc4(plaintext)` puis `rc4(checksum)`. Comme RC4 est un cipher de flux, l'ordre détermine quels bytes du keystream chaque appel consomme — wrong order → ciphertext indéchiffrable côté serveur. | Test `seal_matches_pywinrm_vector` produit `0100000040362a8e94beecd2... ` pour input fixe = même bytes que pyspnego |
| 2 | [src/ntlm/messages.rs:230](src/ntlm/messages.rs#L230) (LM response) | NTLMv2 + AV_TIMESTAMP requiert `LM = 24 bytes de zéros` (anti-replay MS-NLMP 3.1.5.1.2). On envoyait toujours le HMAC réel. | Diff binaire vs pyspnego avec mêmes random fixés → 0 octet de différence sur 418 |
| 3 | [src/asn1.rs:174](src/asn1.rs#L174) (`encode_spnego_response`) | `[0] negState ENUMERATED accept-incomplete` manquait dans le NegTokenResp. Windows CredSSP l'exige même si RFC 4178 le marque optionnel. | Comparaison structure ASN.1 vs capture pywinrm |
| 4 | [src/ntlm/mod.rs:88](src/ntlm/mod.rs#L88) (`NtlmSession::sign`) + [src/asn1.rs:189](src/asn1.rs#L189) (`MECH_TYPE_LIST_NTLM`) + [src/auth/credssp.rs](src/auth/credssp.rs) | Le **mechListMIC** SPNEGO manquait. C'est une signature NTLM 16 bytes sur la mech_type_list, à insérer en `[3] OCTET STRING` du NegTokenResp. **Conséquence non-évidente** : calculer cette signature consomme `seq_num=0`, donc le `seal()` du pubKeyAuth utilise `seq_num=1` (et non 0 comme dans nos premières versions). | Test `sign_matches_pyspnego_mech_list_mic` produit byte-identique à `01000000 02f81117bb3953f7 00000000` |
| 5 | [src/ntlm/messages.rs:51](src/ntlm/messages.rs#L51) | `Type 1 SB offsets = 40` (et non 0) + `version = [0,12,1,0,0,0,0,15]` (et non `[10,0,0,0,0,0,0,15]`). Pixel-perfect avec pywinrm. | Diff binaire round 1 |

**Validation crypto globale** :
[src/ntlm/mod.rs::tests](src/ntlm/mod.rs#L188) contient des tests à vecteurs
déterministes qui forcent `random_session_key=0x10..0x1f` et
`client_challenge=0x20..0x27` puis comparent les sorties bit-à-bit avec ce
que produit pyspnego pour les mêmes inputs. Tous passent.

---

## Refacto HTTP transport

### Pourquoi
`reqwest` n'expose pas d'API garantissant qu'une POST réutilise *exactement*
la même socket TCP qu'une POST précédente. Pour CredSSP c'est rédhibitoire :
l'état TLS interne **vit sur le TCP côté serveur**. Quand reqwest ouvre une
nouvelle socket entre rounds, le serveur perd le contexte et répond `401 + close`.

### Architecture actuelle

```text
                ┌─────────────────────────────────────┐
                │  CredSspConnection (single TCP)     │
   raw HTTP/1.1 │  ┌───────────────────────────────┐  │
   manuel   ───►│  │  tokio_rustls TlsStream       │  │
                │  │  (outer TLS, force TLS 1.2)   │  │
                │  └──────────────┬────────────────┘  │
                │                 │                    │
                └─────────────────┼────────────────────┘
                                  │
                                  ▼ TCP
                              Microsoft HTTPAPI
                                  │
                                  ▼
                          ┌──────────────┐
                          │ CredSSP layer│
                          └──────┬───────┘
                                 ▼
                       OpenSSL inner TLS
                       (TLS-in-TLS via Authorization
                        header b64, MemBio mode,
                        TLS 1.2 forcé)
                                 ▼
                       NTLM Type1 / Type2 / Type3
                       + pubKeyAuth + TSCredentials
```

### Composants
- **CredSspConnection** (~150 lignes dans
  [src/auth/credssp.rs](src/auth/credssp.rs)) : ouvre une seule
  `tokio::net::TcpStream`, fait le handshake TLS extérieur via
  `tokio_rustls::TlsConnector`, écrit du raw HTTP/1.1 à la main et lit la
  réponse en parsant Content-Length.
- **OpenSslMemTls** (même fichier) : wrapper in-memory autour d'OpenSSL pour
  l'inner TLS. Implémente un MemBio (incoming/outgoing buffers) puis
  `SslStream::new()` + `set_connect_state()`. Méthodes :
  `handshake_step / drain_outgoing / feed_incoming / write_plaintext /
  read_plaintext / peer_cert_der`.
- **`x509-cert`** crate pour extraire `subjectPublicKey` du cert serveur
  proprement (vérifié byte-pour-byte identique à notre parser DER manuel).

### Dépendances ajoutées (sous la feature `credssp`)
```toml
hyper-util     = "0.1"   # initialement essayé, abandonné au profit du raw
hyper          = "1"     # idem
tokio-rustls   = "0.26"  # outer TLS
http-body-util = "0.1"
http           = "1"
bytes          = "1"
x509-cert      = "0.2"   # cert parsing
openssl        = "0.10"  # inner TLS in-memory (matching pyspnego)
```

`hyper`/`hyper-util` ne sont plus utilisés dans le code (refacto vers raw
HTTP/1.1) mais sont gardés en feature pour l'instant.

---

## L'erreur exacte qu'on reçoit

```
HTTP/1.1 401 Unauthorized
Server: Microsoft-HTTPAPI/2.0
WWW-Authenticate: Negotiate
WWW-Authenticate: Basic realm="WSMAN"
WWW-Authenticate: CredSSP
Date: Wed, 08 Apr 2026 22:48:00 GMT
Connection: close
Content-Length: 0
```

**Caractéristiques importantes** :
- C'est un **401 fresh challenge** (offre toutes les méthodes d'auth comme
  si on était une nouvelle connexion). Ce n'est PAS un 401 "token invalide"
  qui contiendrait `WWW-Authenticate: CredSSP <continuation-token>`.
- `Connection: close` → le serveur ferme le TCP.
- Arrive **uniquement sur le round 4** (Type3+pubKeyAuth). Les rounds 1-3
  reviennent normalement avec des CredSSP tokens.
- **Avant** ce 401 : l'event log Windows montre `4624 NTLM Logon Success`
  ET event 91 WinRM `Creating WSMan shell on server (vagrant) clientIP=...`
  → le serveur valide notre auth, accepte le SOAP body, et fait avancer
  WSMan jusqu'à créer le shell. Puis quelque part la couche CredSSP /
  HTTPAPI override la réponse de WSMan avec le 401.

**Round 4 = celui où on envoie** :
- `TSRequest version=6` contenant :
  - `[1] negoTokens` = SPNEGO NegTokenResp wrappant NTLM Type 3
    (avec mechListMIC en `[3]`)
  - `[3] pubKeyAuth` = `seal(seq=1, SHA256(magic + nonce + SPK))`
  - `[5] clientNonce` = 32 octets aléatoires

---

## Tout ce qu'on a essayé qui n'a pas fixé le bug

### Côté HTTP / transport
- ✗ `reqwest` direct (commençait par `connection: close` immédiatement)
- ✗ `hyper` 1.x avec `client::conn::http1::handshake` → "operation canceled"
  parce que pyspnego fait des choses bas-niveau qu'hyper ne reproduit pas
- ✗ raw HTTP/1.1 sur `tokio_rustls::TlsStream<TcpStream>` (notre solution
  finale, propre, persistante — mais ne fixe pas le bug round 4)
- ✗ Headers minimaux (`Host`, `Content-Length`, `Authorization`)
- ✗ Headers identiques à pywinrm (`User-Agent: Python WinRM client`,
  `Accept-Encoding: gzip, deflate, zstd`, `Accept: */*`,
  `Connection: Keep-Alive`)
- ✗ Authorization placé avant ou après Content-Type/Content-Length
- ✗ `Content-Type: application/soap+xml;charset=UTF-8` présent ou absent
- ✗ Body SOAP envoyé en chaque round VS body vide
- ✗ Body SOAP exact de pywinrm (`Shell Create` 1683 bytes via
  `CREDSSP_FORCE_BODY=/tmp/pyw_body.txt`)
- ✗ Body envoyé en un seul `write_all()` vs deux (head + body séparés)
- ✗ Avec ou sans primer round (POST sans Authorization)

### Côté TLS
- ✗ rustls 0.23 avec ring + TLS 1.3 outer (par défaut)
- ✗ rustls 0.23 avec ring + **TLS 1.2 outer forcé** (`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`)
- ✗ rustls inner TLS (TLS 1.2 forcé, `Resumption::disabled()`)
- ✗ **OpenSSL inner TLS** via MemBio (= exactement ce que fait pyspnego)
- ✗ `set_min/max_proto_version(TLS1_2)` côté OpenSSL
- ✗ SNI = "credssp" / hostname / IP littéral / disabled
  (`use_server_name_indication(false)`)
- ✗ `verify_hostname(false)` + `SslVerifyMode::NONE` côté OpenSSL

**→ Le fait que rustls ET OpenSSL produisent le même comportement défaillant
élimine définitivement toute hypothèse "bug TLS rustls".**

### Côté NTLM / CredSSP message
- ✓ NTLMv2 hash (NTOWFv2 = HMAC-MD5(NTHash, UPPER(user)+domain), domain="")
- ✓ NTProofStr = HMAC-MD5(ntowfv2, server_challenge||temp_blob)
- ✓ ExportedSessionKey via random + RC4(KEK, random) en EncryptedRandomSessionKey
- ✓ Sealing/signing keys dérivées via les magic strings MS-NLMP 3.4.5.3
- ✓ MIC = HMAC-MD5(exported_session_key, Type1||Type2||Type3_avec_zéros_au_MIC)
- ✓ mechListMIC = NtlmSession::sign(`30 0c 06 0a 2b 06 01 04 01 82 37 02 02 0a`)
  avec seq=0
- ✓ pubKeyAuth = seal(seq=1, SHA256("CredSSP Client-To-Server Binding Hash\0" + nonce + spk))
- ✓ SubjectPublicKey extraction (PKCS#1 RSAPublicKey, 140 bytes pour RSA-1024)
  vérifiée byte-identique entre notre parser DER manuel et `x509-cert`

### Diagnostic
- ✓ tcpdump + SSLKEYLOGFILE outer + Wireshark décrypté pour ours et pywinrm
- ✓ Hook urllib3 dans pywinrm pour dumper bytes envoyés/reçus
- ✓ Comparaison head HTTP byte-pour-byte avec pywinrm
- ✓ Force déterministe `os.urandom` côté pywinrm + env vars
  `CREDSSP_FIXED_CC` / `CREDSSP_FIXED_RSK` côté nous → diff bit-à-bit du
  Type 3 produit (0 octets de différence avec mêmes inputs)
- ✓ Lecture event log Windows (Security 4624/4625, WinRM/Operational)
- ✓ `auditpol /set /subcategory:"Logon" /failure:enable` pour avoir Sub Status
- ✓ `wevtutil cl Security` entre tests pour isoler les events de notre run

---

## Variables non-testées (pistes restantes)

### Piste 1 — Version CredSSP négociée — **ÉLIMINÉE ✓**
On a ajouté `eprintln!("[CREDSSP] server CredSSP version: {} (negotiated: {})",
ts_resp.version, negotiated_version)` après le décodage du Type 2. Le serveur
répond `version=6`, on négocie `6`. Tout est aligné. Pas un problème de
version.

### Piste 2 — Diff `encode_ts_request` byte-pour-byte vs pyspnego — **ÉLIMINÉE ✓**
Forcé tous les randoms identiques entre les deux côtés (CC=`20..27`,
RSK=`10..1f`, nonce=`30..4f`), capturé pyspnego via hook
`spnego._credssp_structures.TSRequest.pack()`, dumpé notre TSRequest via
`CREDSSP_DUMP=1`, diff binaire. Résultat :

| Lens | Diff bytes |
|---|---|
| ours = 576 / pyw = 576 | 96 octets diffèrent |

**Toutes** les diffs sont des outputs cryptographiques (MIC, NTProofStr,
EncryptedRandomSessionKey, pubKeyAuth checksum, pubKeyAuth ciphertext,
timestamp dans temp blob et AV_TIMESTAMP) qui dépendent du **timestamp
serveur** (qui change de quelques secondes à chaque run, le serveur
l'envoie dans Type 2 AV_TIMESTAMP).

**Tous les bytes structurels (tags ASN.1, longueurs, tags context, ordre,
SBs NTLM Type 3, mechListMIC, le SPK, la nonce, etc.) sont byte-identiques.**
Notre encodeur ASN.1 est correct.

### Piste 3 — TSCredentials encoding
On atteint jamais le round 5 (TSCredentials), donc l'encodage n'est jamais
testé contre le serveur. Mais si le bug du round 4 est en fait un bug du
sealing **lors d'une opération qu'on fait avant** (ex: si `mechListMIC` ou
`encode_ts_credentials` consomme un seq_num qu'on ne devrait pas), ça pourrait
expliquer la chose.

**À tester** : vérifier que le seq_num de notre `NtlmSession` est exactement
1 quand on appelle `seal()` pour `pubKeyAuth`. (Spoiler : oui, on a
seq=0 → consommé par `mechListMIC = sign()` → seq=1 → consommé par
`pubKeyAuth = seal()` → seq=2 → consommé plus tard par `TSCredentials = seal()`).

### Piste 4 — Channel binding sur le cert OUTER
On ne fait pas de channel binding sur le cert HTTPS extérieur. NTLM via
HTTPS classique utilise un AV_CHANNEL_BINDINGS, mais en CredSSP la sécurité
vient du `pub_key_auth` sur le cert INTÉRIEUR. Pas évident que Microsoft
en exige aussi sur l'extérieur.

**À tester** : ajouter un AV_CHANNEL_BINDINGS dans le Type 3 calculé sur le
cert HTTPS extérieur, voir si ça change quelque chose. Probable non puisque
pywinrm ne le fait pas non plus.

### Piste 5 — Tracing CredSSP côté Windows — **PARTIELLEMENT FAIT ✓**
Capturé via `logman create trace credssp_dbg -ets -pf C:\providers.txt` avec
9 providers : Schannel, NTLM Security, Microsoft-Windows-NTLM, Schannel-Events,
HttpService, WinRM, Security-Netlogon. Décodé via `tracerpt -of CSV`.

**Activé aussi** les Analytic logs WinRM et CAPI2 :
```powershell
wevtutil sl "Microsoft-Windows-WinRM/Analytic" /enabled:true
wevtutil sl "Microsoft-Windows-CAPI2/Operational" /enabled:true
```

**Résultats** :

1. **NTLM réussit côté lsass** :
   ```
   Microsoft-Windows-NTLM 4023:
     process="lsass" pid=0x328
     user="vagrant" domain="Null" workstation="POSTE-FIXE-LOIC"
     flags=0xE28A8235 ntlm_version="NTLMv2"
     channel_binding="Present" target_name="HTTP/192.168.96.1"
     flags2=0x2 "MIC Provided"
     status=STATUS_SUCCESS
   ```
   `STATUS_SUCCESS` confirme : Type 3 NTLM accepté, mechListMIC validé.
   Notre cryptographie est correcte côté serveur.

2. **Juste après NTLM, WinRM Analytic event 1294 (Warning)** fire :
   ```
   1294|2|"Sending HTTP 401 response to the client and disconnect the
        connection after sending the response"
   ```
   Le serveur prend une décision **explicite** de drop la connexion. Action
   suivie immédiatement par `Microsoft-Windows-HttpService SslDisconnReq`
   puis `FastResp 401`.

3. **CAPI2 Operational montre** :
   ```
   11|Error|Build Chain
   ```
   plusieurs fois pendant la séquence credssp. Cela peut être normal (le
   cert TLS interne est self-signed donc Build Chain échoue toujours).
   Pyspnego trigger probablement les mêmes events. Pas distinctif.

4. **Les events critiques entre fin-NTLM et 1294 sont des "Unknown"
   events** (providers WinRM/CredSSP internes sans manifest exposé) :
   - GUID `eb7563ce-f4ea-3990-0b4d-7a783ed3bb45` (events 10-23)
   - GUID `56149e46-630a-3677-2133-7c7ef961a653` (events 10-26)
   - GUID `ddbf5b7e-a5a6-371c-ab87-56a6ac972d14` (events 10-11)

   Sans manifest impossible de décoder le payload de ces events, qui sont
   probablement les events de la couche **CredSSP server-side processing
   du pubKeyAuth**. C'est exactement où le rejet doit se passer mais on
   n'a pas le détail.

**Conclusion ETW** : on a confirmé que le serveur **explicitement** drop
la connexion via WinRM 1294, juste après que NTLM ait validé. Le rejet est
au niveau de la couche CredSSP post-NTLM (probablement la vérification
pubKeyAuth), mais le payload détaillé des events CredSSP serveur n'est
pas accessible sans symboles Microsoft.

**Prochaine étape envisageable** : utiliser **WinDbg** sur la VM pour
attacher le debugger au process lsass/svchost et breakpoint dans les
fonctions CredSSP de Schannel. Très lourd. Ou demander à jborean93 si
les task GUIDs lui parlent.

### Piste 6 — Demander à jborean93
Maintainer de pyspnego, requests-credssp, smbprotocol. Connait Microsoft
CredSSP de l'intérieur. Préparer un dossier complet :
- pcaps des deux flows (notre `/tmp/ours.pcap` + pywinrm `/tmp/pyw2.pcap`)
- keylogs SSL pour décrypter
- dump des bytes Type 3 / pubKeyAuth / mechListMIC déterministes
- résultat de la piste 5 si possible

### Piste 7 — Reboot Windows — **TESTÉ ✓ ÉLIMINÉE**
VM rebootée à froid via `Restart-VM 'ferrum-wintest' -Force`, port-proxy WSL
refait. Résultat :

- ✅ pywinrm CredSSP : **fonctionne** (`win-ttstanuq08s\vagrant`)
- ❌ notre impl CredSSP : **reproduit exactement le même 401 + close** sur
  round 4, avec les mêmes bytes structurels, le même `[CREDSSP] server
  CredSSP version: 6 (negotiated: 6)`.

**Ce n'est donc pas un état serveur sale**. Le bug est 100% côté client,
dans notre code, dans une variable qu'on n'a pas encore isolée malgré tous
les tests structurels.

---

## Fichiers modifiés (refacto inclus)

| Fichier | Changement |
|---|---|
| [Cargo.toml](Cargo.toml) | +6 deps optionnelles sous feature `credssp` |
| [src/auth/credssp.rs](src/auth/credssp.rs) | Réécriture complète : `CredSspConnection` + `OpenSslMemTls` + `MemBio` + flow refactoré, ~600 lignes propres |
| [src/auth/mod.rs](src/auth/mod.rs) | (inchangé, le trait `AuthTransport` reste pareil) |
| [src/asn1.rs](src/asn1.rs) | `encode_spnego_response` + `[3] mechListMIC`, `MECH_TYPE_LIST_NTLM`, `negState` |
| [src/ntlm/mod.rs](src/ntlm/mod.rs) | `NtlmSession::sign()` (16 bytes signature only), `seal/unseal` corrigés (RC4 order), tests à vecteurs |
| [src/ntlm/messages.rs](src/ntlm/messages.rs) | LM zeros si MIC, version `00 0c 01 ...`, SB offsets Type 1, env vars `CREDSSP_FIXED_*` pour les tests déterministes |
| [src/transport.rs](src/transport.rs) | (modifs cosmétiques pour reqwest pool size, finalement non bloquantes) |

## Commits clés (reste à faire si on commit)

- `feat(credssp): rewrite transport with raw HTTP/1.1 over single TLS socket`
- `feat(credssp): switch inner TLS from rustls to OpenSSL MemBio (matches pyspnego)`
- `fix(credssp): add SPNEGO mechListMIC computation`
- `fix(credssp): zero LM response when MIC required (NTLMv2 + timestamp)`
- `fix(credssp): correct RC4 stream order in NtlmSession::seal/unseal`
- `fix(credssp): add negState ENUMERATED in NegTokenResp`
- `fix(credssp): align NTLM Type 1 SB offsets and version field with pywinrm`
- `test(ntlm): add deterministic vector tests against pyspnego`

## Environnement de test

- VM Vagrant + Hyper-V (Windows Server 2019, hostname WIN-TTSTANUQ08S)
- WinRM HTTPS sur 5986 (cert auto-signé `WSMAN-WIN-TTSTANUQ08S`, RSA-1024)
- Credentials : `vagrant` / `vagrant` (compte local, pas de domaine)
- Pont WSL2 → VM via `gsudo netsh interface portproxy` (port 55986 → 5986)
- Reference : `pywinrm` 0.5.0 + `requests-credssp` 2.x + `pyspnego` (toutes
  installées dans `/tmp/credssp-venv`)

## Ce qui marche actuellement

- 289 tests unitaires verts (`cargo test --features credssp --lib`)
- Clippy clean (`cargo clippy --features credssp`)
- Tests d'intégration NTLM/HTTPS classique (Basic, NTLM avec CBT, Certificate)
  toujours OK contre la même VM

## Ce qui ne marche pas

- `cargo test --features credssp --test integration_real credssp_run_command_whoami -- --ignored`
  panique avec `AuthFailed("CredSSP: NTLM auth: no CredSSP token")` sur le
  round 4, même si le serveur côté Windows valide bien notre auth (event 4624)
  et que l'ETW capture `STATUS_SUCCESS` côté lsass.

---

## Impact fonctionnel : qu'est-ce que ce bug bloque vraiment ?

**Pour 95 % des cas d'usage : RIEN.** CredSSP n'est pas nécessaire pour
exécuter des commandes sur un serveur Windows distant via WinRM.

| Cas d'usage | Auth nécessaire | Marche aujourd'hui ? |
|---|---|---|
| `winrs cmd hostname` (run a command) | Basic / NTLM / Kerberos | ✅ |
| Lire un fichier sur le serveur cible | NTLM / Kerberos | ✅ |
| Lancer un script PowerShell | NTLM / Kerberos | ✅ |
| Démarrer / arrêter un service | NTLM / Kerberos | ✅ |
| WMI queries (`Get-WmiObject Win32_OperatingSystem`) | NTLM / Kerberos | ✅ |
| Upload / download de fichiers | NTLM / Kerberos | ✅ |
| Exécuter une commande sur Windows qui doit **accéder à une autre machine du réseau** (file share, autre serveur AD, base SQL distante...) | **CredSSP requis** | ❌ |
| PowerShell remoting via une jump box (double-hop) | **CredSSP requis** | ❌ |
| Démarrer une commande qui authentifie l'utilisateur sur un share `\\fileserver\data` | **CredSSP requis** | ❌ |

**CredSSP existe pour résoudre le « double hop problem »** : par défaut,
quand tu te connectes en NTLM ou Kerberos sur un serveur Windows, le serveur
peut exécuter du code sous ton identité MAIS il ne peut **pas réutiliser
tes credentials** pour accéder à un autre serveur. Tu obtiens des
`Access Denied` dès que ta commande touche une ressource réseau secondaire.

CredSSP délègue les credentials en clair au serveur (via le tunnel TLS interne
+ pubKeyAuth), ce qui permet au serveur d'agir vraiment en ton nom partout.

### En pratique pour cette crate

- **Toutes les auth méthodes courantes fonctionnent** : Basic, NTLM (avec
  CBT en HTTPS), Kerberos, Certificate. Les ~289 tests unitaires + tests
  d'intégration NTLM/HTTPS sont verts.
- **Le module CredSSP n'est pas intégrable en l'état** pour les use cases
  double-hop. Il faut soit :
  - Pour le double-hop : utiliser **Kerberos avec délégation contrainte**
    côté Active Directory (la solution MS « propre » qui évite CredSSP).
  - Ou attendre une résolution du bug CredSSP ici.
- Le code CredSSP **reste mergeable** : tout est sous la feature
  `credssp` (opt-in), avec ~600 lignes de transport raw HTTP/1.1 propre,
  les helpers crypto vérifiés bit-perfect, et tous les tests unitaires
  passent. Aucun risque de régression sur les autres auth méthodes.

**TL;DR du bug** : CredSSP marche jusqu'à 95 % du protocole, mais Microsoft
HTTPAPI rejette silencieusement notre `pubKeyAuth` (ou un truc juste après)
au moment où il faudrait basculer sur la phase « delegate credentials ».
Sans CredSSP fonctionnel, **on ne perd pas la fonctionnalité WinRM de base**,
on perd **la délégation de credentials pour les scénarios double-hop**.
