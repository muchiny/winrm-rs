# Matrice de validation live de winrm-rs

Campagne du 2026-10-21, branche `test/live-coverage`. Chaque `✅` ci-dessous est
adossé à un test nommé qui a réellement passé contre une VM Windows ; rien n'est
déduit de la lecture du code.

## Commits testés

| Crate | Commit | Ce qui a été exécuté |
|---|---|---|
| `winrm-rs` | `d13c982` (branche `test/live-coverage`, dernier commit de code ou de test après le troisième tour de correctifs de T18) : suite live complète contre Server 2025 avec `--features credssp,__internal` (81 tests, variables du banc exportées à la main, `vm-connect.sh` restant bloqué sur gsudo), **81 passés, 0 échoué** (218 s, parallélisme par défaut) ; à `3a6e948` : 81 passés (213 s) ; à `2d5cf66` : 81 passés (209 s) ; même résultat à `d306efa` (213 s). Avant : `d69030d` (dernier commit de code ou de test, après `3c6fdbf` qui ajoute les API `*_with_timeout` ; le commit de documentation qui le suit ne touche que le `CHANGELOG` et ce document ; les runs ci-dessous ont été faits sur cet arbre) | Suite live complète contre Server 2025 avec `--features credssp,__internal` (80 tests), les deux `eval` du banc faits : **80 passés, 0 échoué** (463 s) avec `--test-threads=1` ; en parallélisme par défaut, **80 passés, 0 échoué** (207 s ; `shell_run_command_times_out` reste sensible à la charge). Server 2012 R2 (VM reconstruite) : les tests NTLM et deux tests Basic seulement, voir « Limites connues ». Runs précédents : à `f30b7f3` et `92341f6`, 78 passés en série comme en parallèle ; à `4f229dc`, 78 passés en série, 77 passés et 1 échoué (`shell_run_command_times_out`) en parallèle ; à `4cbebfb`, 66 passés en série, 65 passés et 1 échoué en parallèle. Les tests à timeout court se lisent plus fiablement avec `--test-threads=1` (voir l'en-tête de `tests/integration_real.rs`). |
| `winrm-rs` (Kerberos) | `d13c982` (troisième tour : cible du vérificateur prise de l'URL analysée, épinglage refusé sans cible, tout autre nom refusé une fois épinglé ; avant lui `3a6e948`, certificat épinglé après la sonde) ; groupes `kerberos` (7 passés) et `dc_cbt` (2 passés) rejoués à `d13c982`, le groupe `allow_unencrypted_false` à `3a6e948` (code TLS seul changé depuis) | Contre le contrôleur de domaine `winrm.test` (banc séparé, `tests/vagrant/dc/README.md`), avec `--features kerberos` et un TGT obtenu par `kinit vagrant@WINRM.TEST`, le 2026-10-22 : `... kerberos -- --ignored --skip allow_unencrypted_false --skip dc_cbt` → **7 passés, 0 échoué** (23 s) ; `... allow_unencrypted_false -- --ignored --test-threads=1` → **3 passés, 0 échoué** (298 s ; `AllowUnencrypted` remis à `true` après chacun) ; `... dc_cbt -- --ignored --test-threads=1` → **2 passés, 0 échoué** (15 s ; `CbtHardeningLevel` remis à `Relaxed` après chacun). Runs précédents : `2d5cf66` (6 + 3 + 2 passés, sans épinglage) ; `ac88145`/`dc33bea` (5 + 2 passés, sans binding de canal) ; `f8a1272`, 3 passés sur HTTP sans chiffrement. |
| `psrp-rs` | `4a79189` (`origin/main`) ; mesuré au plus tard contre `winrm-rs` `d69030d`, pas rejoué aux commits de T18 | Suite live (8 tests) contre le `winrm-rs` local (`[patch.crates-io]`, worktree jetable) : **8 passés, 0 échoué** contre `winrm-rs` `4cbebfb` (Basic), puis contre `84f1898` en Basic et en NTLM sur HTTP. Contre `winrm-rs` `4f229dc`, `92341f6`, `f30b7f3` puis `d69030d` (scellement qui échoue fermé et sans renvoi, une connexion authentifiée par échange, CBT de la connexion) : **8 passés** avec Basic sur HTTP (réglage par défaut de la suite) et **8 passés** avec `PSRP_INTEGRATION_AUTH=ntlm` (NTLM scellé sur HTTP), à chaque commit. Ce run NTLM, à travers un relais TCP enregistreur qui garde chaque connexion à part : 8 connexions (une par client), 2 requêtes `Negotiate` par connexion, 72 requêtes et 72 réponses `multipart/encrypted`, aucun corps de requête en clair (les Type 1 et Type 3 n'en portent pas), aucun HTTP 400 ni 500. |
| `bridge-mcp` | `f44a5fa` (v4.0.2, worktree jetable ; `origin/main` est maintenant `ec9310e`) ; mesuré au plus tard contre `winrm-rs` `d69030d`, pas rejoué aux commits de T18 | Smoke en ligne de commande par `winrm` puis par `psrp` (hôtes NTLM sur HTTP) : `hostname` renvoie `winrm-2025`, `Get-Date` renvoie la date du banc (2026-10-21), sur les deux protocoles. Fait contre `winrm-rs` `4cbebfb`, `84f1898`, `4f229dc`, `92341f6`, `f30b7f3`, puis `d69030d` (avec `psrp-rs` `4a79189`) : 4 appels sur 4 réussis à chaque fois (1,8 à 2,7 s chacun à `d69030d`), à travers le relais enregistreur : 4 connexions, 2 requêtes `Negotiate` par connexion, 26 requêtes scellées, aucun corps de requête en clair, aucun HTTP 400. Journal d'audit redirigé vers un fichier jetable. |

Banc : une VM Windows Server 2025 (`winrm-2025`) sous Hyper-V, atteinte par
`tests/scripts/vm-connect.sh` (HTTP `55985`, HTTPS `55986`, compte `vagrant`).
Kerberos : une seconde VM, contrôleur de domaine Windows Server 2025 de la
forêt `winrm.test` (VM Hyper-V `winrm-rs-dc`, hôte `dc`), atteinte par
`tests/scripts/vm-connect-dc.sh` (WinRM HTTP `57985`, KDC TCP `57088`, compte
`WINRM\vagrant`) ; voir `tests/vagrant/dc/README.md`.
Au départ de la campagne (avant tout ajout de test), les 52 tests live
existants passaient : 52 passés, 0 échoué, 0 sauté (sans la feature `credssp`).

Les tests ajoutés par la campagne portent le total à 76, ou 78 avec la
feature `credssp` (`credssp_run_command_whoami` et
`silent_command_completes_over_credssp` sont sous `#[cfg(feature =
"credssp")]`) : 13 jusqu'à `4cbebfb`, 3 avec `9ceaaba` (une commande
silencieuse par méthode d'authentification live), 5 avec `84f1898`
(transferts, annulation, Ctrl+C et shells concurrents en NTLM scellé, plus
la référence Basic des shells concurrents), 1 avec `9c61ae8`
(`streaming_clixml_stderr_yields_records_before_exit`), puis 3 avec
`4f229dc` (1,5 Mo de sortie en NTLM scellé avec deux `MaxEnvelopeSize`,
`EncryptionMode::Always` sur HTTPS). Les runs complets à `4f229dc` les
exécutent tous.
Les tests Kerberos, sous `#[cfg(feature = "kerberos")]`, s'y ajoutent
(`kerberos_run_command_whoami`, `kerberos_two_commands_on_one_client`,
`silent_command_completes_over_kerberos`, puis avec `dc33bea`
`kerberos_over_https_whoami`, `kerberos_encryption_always_over_https`,
`kerberos_sealed_with_allow_unencrypted_false`,
`kerberos_unsealed_with_allow_unencrypted_false_is_a_clear_error` et la
préparation `setup_dc_https_listener`, puis avec `33fda8a`, `2d5cf66` et `3a6e948`
`kerberos_channel_binding_through_a_tls_relay_is_refused`,
`kerberos_channel_binding_split_relay_fails_at_the_handshake`,
`always_seals_inside_tls_seen_by_a_relay_with_dc_cbt_none`,
`kerberos_over_https_with_dc_cbt_strict` et
`sealed_download_after_upload_stays_on_its_connection_allow_unencrypted_false`) ; ils visent le contrôleur de domaine
et ne font pas partie des runs complets contre Server 2025.

## Découvertes

Trois vrais défauts du crate ont été révélés par les nouveaux tests live. Les
trois sont **corrigés** sur cette branche ; D1 et D2 avec l'accord de
l'utilisateur, D3 en complétant D1 (voir sa section). Il n'y a donc aucun `❌`
ouvert.

### D1 : un `w:TimedOut` sur Receive faisait échouer toute commande silencieuse

- **Reproduction, au commit avant le correctif** (dans un checkout de
  `d5b4099`, par exemple `git worktree add <dossier> d5b4099`, banc 2025
  branché) :
  `cargo test --test integration_real -- --ignored signal_terminate_stops_running_command shell_run_command_times_out`
  - `signal_terminate_stops_running_command` échoue après environ 60 s :
    `first receive: Soap(Fault { code: "w:TimedOut", ... })`.
  - `shell_run_command_times_out` échoue après 5 s : `Err(Soap(Fault w:TimedOut))`
    au lieu de `Err(Timeout(10))`.
  - Hors test, `run_powershell("Start-Sleep 75; 'ok'")` avec la configuration par
    défaut renvoie la même erreur après 66 s.
- **Cause.** Quand un Receive ne trouve aucune sortie pendant
  `operation_timeout_secs`, le serveur répond par le fault WS-Management
  `w:TimedOut`, qui veut dire « rien pour l'instant, relance un Receive ». Le
  crate renvoyait ce fault comme `WinrmError::Soap` et aucune boucle de
  scrutation (`run_command`, `run_powershell`, `Shell::run_command`,
  `Shell::receive_next`) ne le traitait comme une scrutation vide, si bien que
  toute commande muette plus de 60 s (par défaut) échouait. Une scrutation
  manuelle qui relançait Receive sur le fault voyait la commande survivre et
  rendre sa sortie, donc rien n'était perdu côté serveur.
- **Commits qui corrigent.** `aedf2a4` (correctif : le fault `TimedOut` sur
  Receive devient une scrutation vide), puis les tests durcis par `eb25ed7`,
  `a43cf4b` et `a252246` (les trois tests concernés passent à un timeout
  d'opération de 15 s, plus un test de régression sur le décodeur CLIXML coupé
  par une scrutation `TimedOut`).
- **Vérifié après correctif.** Les trois tests live concernés passent
  (`signal_terminate_stops_running_command`, `shell_run_command_times_out`,
  `silent_command_longer_than_operation_timeout_completes`) et la suite
  complète fait 65/65 à `4cbebfb` (sans la feature `credssp`).
- **Complément (après `4cbebfb`) : le correctif n'atteignait que Basic et NTLM non
  scellé.** Certificate, Kerberos et CredSSP rendaient un HTTP 500 portant un
  fault SOAP comme `AuthFailed`, de sorte que le `TimedOut` n'arrivait jamais
  au traitement « scrutation vide ». Reproduction : dans un checkout de
  `9ceaaba`, remettre les sources d'avant (`git checkout d4bc927 -- src/`) et
  lancer `cargo test --features credssp,__internal --test integration_real --
  --ignored silent_command` (avec les deux `eval` du banc) :
  `silent_command_completes_over_certificate_auth` échoue sur
  `AuthFailed("Certificate auth HTTP 500 Internal Server Error: <s:Envelope …
  w:TimedOut …")` et `silent_command_completes_over_credssp` sur
  `AuthFailed("CredSSP HTTP 500: …")`. Corrigé par `7a9d65a` (un seul mappage
  statut vers erreur, `auth::error_for_status`, pour les six points d'appel).
  Vérifié live : une commande silencieuse 20 s avec un timeout d'opération de
  15 s se termine en Basic, NTLM scellé sur HTTP, Certificate et CredSSP.
  Kerberos, vérifié ensuite contre le contrôleur de domaine `winrm.test` :
  `silent_command_completes_over_kerberos` passe (22 s).

### D3 : le scellement NTLM sur HTTP ne fonctionnait pas, tout repartait en clair

- **Trouvé en mesurant D1 sur NTLM sur HTTP** (configuration par défaut,
  `EncryptionMode::Auto`). Reproduction : dans un checkout de `9ceaaba`,
  `git checkout d4bc927 -- src/`, puis
  `cargo test --test integration_real -- --ignored silent_command_completes_over_ntlm_sealed_http` :
  le test échoue avec 14 requêtes `Authorization: Negotiate` au lieu de 2
  (une poignée de main NTLM par requête).
- **Cause.** `seal_body` plaçait un CRLF entre la charge scellée et la
  frontière finale `--Encrypted Boundary--`. Server 2025 répond 400 à chaque
  requête ainsi formée ; le transport prenait ce 400 pour une session
  expirée, se réauthentifiait sur une nouvelle connexion et renvoyait la
  requête **en clair**. Avec `Auto` sur HTTP comme avec `Always`, aucun
  message n'était donc jamais scellé. `unseal_body` avait le défaut miroir
  (il attendait un CRLF que Windows n'envoie pas). Une fois le format
  corrigé, un second défaut est apparu : Windows scelle aussi le HTTP 500 du
  fault, et le transport cherchait le fault dans le corps encore chiffré,
  donc chaque `TimedOut` provoquait une réauthentification et un Receive
  rejoué en clair (4 requêtes `Negotiate` au lieu de 2). Le banc autorise le
  trafic non chiffré (`AllowUnencrypted = true`, posé par le `Vagrantfile`),
  ce qui masquait le repli en clair.
- **Commits qui corrigent.** `4539374` (format MIME aligné sur ce que Windows
  envoie et ce que pypsrp construit) et `ca335e5` (déchiffrer un HTTP 500
  scellé avant d'y chercher le fault ; la session scellée est conservée).
- **Vérifié après correctif.** `silent_command_completes_over_ntlm_sealed_http`
  passe à travers un relais TCP qui enregistre le trafic : 1 réponse HTTP 500
  (le `TimedOut`), 2 requêtes `Negotiate` (une seule poignée de main), 6
  requêtes `multipart/encrypted`. Les tests `ntlm_*` passent, ainsi que les
  tests `ntlm_sealed_*` ajoutés ensuite (transferts, annulation, Ctrl+C,
  shells concurrents en NTLM scellé), la suite live de `psrp-rs` en NTLM sur
  HTTP et le smoke `bridge-mcp` (lignes « Commits testés »).
- **Fermé ensuite (`657570a`) : le repli en clair et le verrou global.** Les
  correctifs ci-dessus laissaient deux chemins en clair (le corps SOAP porté
  par la requête Type 3, et toute requête scellée en échec rejouée en clair
  après une nouvelle poignée de main, donc exécutable deux fois) et un verrou
  tenu pendant tout l'échange. Désormais : Type 3 à corps vide ; aucune
  requête scellée n'est renvoyée, pas même sur un 401 (`62844d9` : un
  attaquant peut faire exécuter la requête par le serveur puis répondre 401
  lui-même, et aucune preuve côté client, comme une nouvelle connexion TCP,
  ne l'exclut, puisqu'il tient le côté serveur de la connexion
  authentifiée) ; tout échec est une erreur et la connexion est jetée ; une réponse annoncée scellée qui ne se
  déchiffre pas est une erreur ; `unseal_body` vérifie toute la trame ; une
  connexion authentifiée par échange en cours, au plus 8 au repos. Vérifié
  par les tests `ntlm_sealed_*` et `silent_command_completes_over_ntlm_sealed_http`
  avec le relais qui garde chaque connexion à part : aucun corps de requête
  en clair, 2 requêtes `Negotiate` par connexion.

### D2 : `AuthMethod::Certificate` n'authentifiait jamais

- **Reproduction, au commit avant le correctif** (checkout de `d5b4099`, banc
  2025 avec le banc certificat préparé par
  `eval "$(tests/scripts/make-client-cert.sh)"` puis le test de préparation) :
  `cargo test --test integration_real -- --ignored setup_certificate_auth`
  suivi de
  `cargo test --test integration_real -- --ignored certificate_auth_whoami`
  - `certificate_auth_whoami` échoue :
    `AuthFailed("Certificate auth HTTP 401 Unauthorized: ")`.
  - Au même commit, `certificate_auth_unmapped_cert_is_rejected` passe pour la
    mauvaise raison (toutes les requêtes reçoivent 401). Il n'est
    discriminant qu'à partir du correctif.
- **Cause.** D'une part le transport installait sa configuration rustls avec
  `with_no_client_auth()`, ce qui faisait abandonner l'identité cliente à
  `reqwest` : aucun certificat n'était présenté dans la poignée de main TLS
  (`openssl s_server -Verify 1` : « peer did not return a certificate »). D'autre
  part les requêtes n'envoyaient pas l'en-tête
  `Authorization: http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual`
  dont WinRM a besoin pour mapper le certificat (avec lui : certificat valide
  donne 500, donc authentifié ; certificat d'une autre CA donne 401 ; sans
  certificat donne 503).
- **Commits qui corrigent.** `3a524d9` (présenter le certificat et l'en-tête
  `Authorization`), puis `4cbebfb` (durcissement : lecture bornée des fichiers
  PEM, `Certificate` sur HTTP en clair devient une `AuthFailed` à la
  construction, message dédié pour une clé chiffrée, test certificat + clé dans
  un seul fichier, test mTLS en processus qui ne dépend plus de l'environnement
  proxy).
- **Vérifié après correctif.** `certificate_auth_whoami` renvoie le compte
  mappé, `certificate_auth_unmapped_cert_is_rejected` reçoit 401 pour un
  certificat d'une CA non approuvée, et la suite complète fait 65/65 à
  `4cbebfb` (sans la feature `credssp`). L'hypothèse du plan (renégociation TLS que rustls ne gère pas) est
  réfutée : avec `clientcertnegotiation=enable`, le serveur envoie le
  `CertificateRequest` dans la poignée de main initiale.
- **État laissé sur le banc 2025** (par `setup_certificate_auth`, idempotent) :
  la CA de test dans `Root` et `TrustedPeople`, `Auth\Certificate` activé, un
  mappage de certificat client, `clientcertnegotiation` activé sur
  `0.0.0.0:5986`.

Historique complet des commits de la campagne :
`git log --oneline 2fdc39d..d69030d`, plus le commit de documentation qui
suit. `2fdc39d` est l'instantané de travail de l'utilisateur, hors de cette
campagne.

## Légende

| Valeur | Sens |
|---|---|
| `✅ <date>` | Test live passé ce jour-là, test nommé dans la colonne « Tests » |
| `⏭ <raison>` | Non mesuré ou non validé, avec la raison |
| `❌ <découverte + lien>` | Défaut ouvert (aucun à ce jour, voir « Découvertes ») |
| texte sans symbole | Relecture de documentation, pas un test live |
| `— non applicable` | La colonne ne concerne pas cette fonctionnalité |

## Matrice : trous de validation de l'inventaire

Tests de `tests/integration_real.rs` sauf mention contraire.

| Fonctionnalité | Tests | Server 2025 | Server 2012 R2 | Domaine (Kerberos) |
|---|---|---|---|---|
| `AuthMethod::Certificate` : certificat client présenté en TLS et mappé (après D2) | `setup_certificate_auth`, `certificate_auth_whoami` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `AuthMethod::Certificate` : certificat d'une CA non approuvée refusé en moins de 30 s | `certificate_auth_unmapped_cert_is_rejected` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Proxy HTTP réussi (forme absolue, NTLM sur HTTP) ; le trafic passe par le proxy, y compris pour `127.0.0.1` | `http_proxy_carries_ntlm_over_http` | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Proxy HTTP `CONNECT` portant du HTTPS | `http_proxy_connect_carries_https` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Proxy SOCKS5 | `socks5_proxy_carries_ntlm` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `max_output_bytes` déclenché, erreur `Transfer`, aucun shell laissé ouvert | `max_output_bytes_aborts_and_releases_shell` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `max_output_bytes` compte les octets bruts du stderr CLIXML | `max_output_bytes_counts_raw_clixml_stderr` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `connect_timeout_secs` respecté | `connect_timeout_is_honoured` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Délai total de `Shell::run_command` (`operation_timeout_secs * 2`) | `shell_run_command_times_out` (timeout d'opération de 15 s) | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Commande silencieuse plus longue que `operation_timeout_secs` menée à terme (après D1), Basic sur HTTP | `silent_command_longer_than_operation_timeout_completes` (20 s de silence, timeout d'opération de 15 s ; 22 à 25 s mesurées) | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Idem, NTLM sur HTTP avec scellement par défaut (après D1 et D3) | `silent_command_completes_over_ntlm_sealed_http` (relais enregistreur : 1 HTTP 500, 2 requêtes `Negotiate`, 6 requêtes scellées ; 21 à 25 s) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Idem, Certificate sur HTTPS (après D1 complété) | `silent_command_completes_over_certificate_auth` (24 s) | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Idem, CredSSP sur HTTPS (`--features credssp`, après D1 complété) | `silent_command_completes_over_credssp` (22 s) | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| Idem, Kerberos sur HTTP (`--features kerberos`), scellé par défaut depuis `ac88145` | `silent_command_completes_over_kerberos` (22 s ; en clair le 2026-10-21, scellé le 2026-10-22) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Messages NTLM réellement scellés sur HTTP (après D3) | `silent_command_completes_over_ntlm_sealed_http` (requêtes `multipart/encrypted`, aucune réauthentification) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Transfert de 200 Ko aller-retour en NTLM scellé sur HTTP, contenu identique | `ntlm_sealed_upload_and_download_large_file` (101 morceaux ; 316 requêtes scellées, une seule poignée de main ; envoi 130 s, soit environ 1,3 s par morceau comme en Basic, réception 2,3 s, réponse la plus grosse 149 Ko) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Annulation (`run_command_with_cancel`) en NTLM scellé sur HTTP, puis le même client resservi | `ntlm_sealed_cancel_long_running_command` (annulation déclenchée une fois Execute et un premier Receive partis scellés : `Cancelled` ; la connexion de l'échange annulé est jetée, la commande suivante sur le même client ouvre une nouvelle connexion (4 requêtes `Negotiate` au total, 2 par connexion) et part scellée, aucun corps en clair) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Ctrl+C en NTLM scellé sur HTTP | `ntlm_sealed_shell_signal_ctrl_c` (5 requêtes scellées, une seule poignée de main) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Shells concurrents sur un même client en NTLM scellé sur HTTP | `ntlm_sealed_concurrent_shells`, référence `concurrent_shells_timings_basic` (tous terminent ; un `echo` lancé pendant le Receive de 10 s de l'autre shell prend 0,19 s en NTLM scellé, contre 10,3 s avant `657570a` et 0,15 à 0,18 s en Basic ; le test exige moins de 3 s ; 2 connexions, une poignée de main chacune) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| 1,5 Mo de sortie en NTLM scellé, `MaxEnvelopeSize` par défaut puis 500 Ko | `ntlm_sealed_large_output_default_envelope`, `ntlm_sealed_large_output_500k_envelope` (sortie complète ; plus grosse réponse HTTP 149 Ko puis 155 Ko : Server 2025 plafonne un Receive vers 150 Ko même avec 500 Ko, bien sous le plafond de 2 Mio du client) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| `EncryptionMode::Always` : NTLM scellé à l'intérieur de HTTPS | `ntlm_encryption_always_over_https` | ✅ 2026-10-21 | ⏭ sauté : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| API bas niveau : `create_shell`, `execute_command`, `receive_output`, `signal_terminate`, `delete_shell` | `low_level_command_lifecycle` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `signal_terminate` arrête une commande en cours | `signal_terminate_stops_running_command` (shell et commande créés avec un client au timeout par défaut ; scrutation, arrêt et vidage avec un timeout d'opération de 15 s) | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `open_psrp_shell` | psrp-rs (`4a79189`) : les 8 tests live, dont `live_smoke_one_plus_one` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `start_command_with_id` | psrp-rs : les 8 tests live (chaque pipeline passe par lui) | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `Shell::disconnect` réussi | psrp-rs : `live_disconnect_reconnect_pool` seul (la déconnexion a réellement eu lieu, sans le message « disconnect not supported ») | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `reconnect_shell` | psrp-rs : `live_disconnect_reconnect_pool` seul | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Chaîne complète `bridge-mcp` (`hostname`, `Get-Date`) par `winrm` et par `psrp` | smoke CLI `bridge-mcp` `f44a5fa` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `AuthMethod::Kerberos` sur HTTP (`--features kerberos`, TGT de `kinit`) : la commande tourne sous le compte du domaine ; messages scellés par défaut depuis `ac88145` | `kerberos_run_command_whoami` (`winrm\vagrant`), `kerberos_two_commands_on_one_client` (deux commandes sur le même client) ; AP-REP vérifié : le scellement exige le jeton du serveur pour établir le contexte | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Kerberos sur HTTPS (écouteur HTTPS du contrôleur, certificat auto-signé, `accept_invalid_certs`) | `kerberos_over_https_whoami` (passé sans changement de code à `82802f9` et `ac88145`, sans binding de canal ; depuis `563ba31` une connexion dédiée authentifiée une fois, binding de canal et AP-REP exigé, passé à `2d5cf66`) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Chiffrement des messages Kerberos sur HTTP avec `AllowUnencrypted = false` (serveur qui l'exige) | `kerberos_sealed_with_allow_unencrypted_false` (relais enregistreur : `whoami` ; transfert de 200 Ko aller-retour identique, 323 requêtes dont 322 scellées, 1 connexion, 1 requête `Negotiate`, aucun corps en clair ; commande silencieuse de 21 s dont les fautes `TimedOut` reviennent scellées en HTTP 500) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| `EncryptionMode::Always` : Kerberos et NTLM scellés à l'intérieur de HTTPS, vu sur le fil | `always_seals_inside_tls_seen_by_a_relay_with_dc_cbt_none` (relais TLS qui termine TLS, `CbtHardeningLevel = None` le temps du test : Kerberos `Always` 5 corps sur 5 scellés, Kerberos `Auto` 0 sur 5, NTLM `Always` 5 sur 5) ; `kerberos_encryption_always_over_https` seul ne prouve que l'acceptation par le serveur | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Kerberos non chiffré (`EncryptionMode::Never`) refusé par `AllowUnencrypted = false` : erreur claire | `kerberos_unsealed_with_allow_unencrypted_false_is_a_clear_error` (HTTP 500 au corps vide ; le message nomme `AllowUnencrypted` et les remèdes ; avant `ac88145` : `AuthFailed("HTTP 500 Internal Server Error: ")`) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Binding de canal Kerberos sur HTTPS (RFC 5929 `tls-server-end-point`) | `kerberos_channel_binding_through_a_tls_relay_is_refused` (relais TLS présentant son propre certificat : refusé sous `Relaxed`, `Auto` et `Always`, aucun corps SOAP n'atteint le relais) ; `kerberos_over_https_with_dc_cbt_strict` (`Strict` : `Auto` et `Always` en direct passent, le relais est refusé) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Binding de canal Kerberos : cas scindé (la sonde passe intacte jusqu'au contrôleur, la connexion suivante est terminée par un relais avec un autre certificat) | `kerberos_channel_binding_split_relay_fails_at_the_handshake` (`Auto` et `Always` : la poignée de main TLS de la connexion de l'AP-REQ est refusée par le vérificateur épinglé, le relais ne reçoit aucune requête ; avant `2bb6443` l'AP-REQ atteignait le relais) ; rejoué sous `Strict` dans `kerberos_over_https_with_dc_cbt_strict` | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Kerberos sur HTTPS (`Auto`, connexion authentifiée une fois) : requêtes suivantes restées sur la connexion authentifiée | mesure ad hoc : envoi de 20 Ko puis téléchargement de 200 Ko sur HTTPS, 10 essais par case, runtime current-thread et multi-thread, 0 et 4 cessions de main : 10/10 partout, exactement 2 connexions TCP par essai (la sonde, puis la connexion authentifiée) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Course du pool des connexions dédiées (requête scellée partie sur une connexion TCP neuve non authentifiée) | `sealed_download_after_upload_stays_on_its_connection_allow_unencrypted_false` (3 tours Kerberos + 3 tours NTLM, chacun sur une seule connexion) ; mesure ad hoc, `AllowUnencrypted = false`, envoi de 20 Ko puis téléchargement de 200 Ko, 10 essais par case : runtime current-thread 0/10 réussis sans céder la main, 10/10 en cédant 4 fois, Kerberos comme NTLM ; runtime multi-thread 10/10 avec 0 ou 4 ; avec `AllowUnencrypted = true` aucun échec (7 téléchargements, 80 sorties de 1,5 Mo) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 (atténué, pas fermé) |
| Doc de `AuthMethod::CredSsp` (disait « Not yet implemented ») | relue contre `credssp_run_command_whoami` | doc corrigée le 2026-10-21 (relecture ; le passage live est la ligne CredSSP plus bas) | — non applicable (relecture de documentation) | — non applicable |

Couverture des API réservées aux crates aval : `open_psrp_shell` et
`start_command_with_id` sont exercées par les 8 tests live de `psrp-rs` ;
`Shell::disconnect` (cas réussi) et `reconnect_shell` ne le sont que par
`live_disconnect_reconnect_pool`. `winrm-rs` n'a pas de test live propre sur un
shell PSRP ; son seul test de `disconnect` est le refus sur un shell cmd,
`shell_disconnect_returns_error_on_cmd_shell`, cité plus bas.

## Matrice : fonctionnalités déjà validées avant la campagne

Les 52 tests live existants (dont les tests de préparation du banc) passaient au
départ (2026-10-21, avant tout ajout) et ont passé à nouveau dans le run complet
à `4cbebfb` (65/65, sans la feature `credssp`), puis à `c46f8c6` (74/74 avec
`--features credssp,__internal`, en série comme en parallèle). `credssp_run_command_whoami`
n'est compilé qu'avec cette feature : il a été exécuté à part le 2026-10-21 à
`4cbebfb` (passé) et dans le run complet à 66 tests. Les noms sont ceux de
`tests/integration_real.rs`.

| Fonctionnalité | Tests | Server 2025 | Server 2012 R2 | Domaine (Kerberos) |
|---|---|---|---|---|
| Basic sur HTTP | `create_and_delete_shell`, `run_command_whoami`, `run_command_with_args`, `run_command_nonzero_exit` | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite ; `create_and_delete_shell` et `run_command_whoami` seulement) | — non applicable |
| Basic sur HTTPS | `basic_over_https_works` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| NTLM sur HTTP | `ntlm_run_command_whoami`, `ntlm_run_powershell`, `ntlm_shell_reuse` | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| NTLM sur HTTPS avec channel binding (CBT) | `ntlm_over_https_with_cbt` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| Les trois `EncryptionMode` (ces tests passaient aussi avant D3 grâce au repli en clair : ils ne prouvent pas le scellement, voir la ligne « Messages NTLM réellement scellés ») | `ntlm_encryption_always`, `ntlm_encryption_never`, `ntlm_encryption_auto_over_http` | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| CredSSP (`--features credssp`) | `credssp_run_command_whoami` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| PowerShell, JSON, Unicode | `run_powershell_version`, `run_powershell_json_output`, `run_powershell_unicode`, `gather_host_facts_json` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Réutilisation d'un shell, démarrage et lecture manuels | `shell_reuse_multiple_commands`, `shell_start_command_and_receive` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| stdin | `shell_send_input_stdin` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Ctrl+C | `shell_signal_ctrl_c` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Annulation | `cancel_long_running_command`, `shell_run_powershell_with_cancel` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Idle timeout | `shell_with_idle_timeout_works` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Répertoire de travail | `shell_with_working_directory` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Variables d'environnement | `shell_with_env_vars` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Transferts de fichiers | `upload_and_download_file`, `upload_and_download_large_file`, `upload_and_download_binary_file` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| WQL | `wql_query_win32_operatingsystem`, `wql_query_win32_service`, `wql_query_custom_namespace`, `wql_query_invalid_namespace` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `max_envelope_size` réduit | `small_max_envelope_size` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Retries | `retry_config_works_with_real_server` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Shells concurrents | `concurrent_shells` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| stderr CLIXML décodé (petit, gros, en flux) | `powershell_stderr_clixml_parsed`, `powershell_large_clixml_stderr_reassembled`, `streaming_large_clixml_stderr_reassembled` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Erreurs sur identifiants de shell invalides | `invalid_shell_id_returns_error`, `double_delete_shell_returns_error`, `command_on_deleted_shell_returns_error` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| `Shell::disconnect` refusé proprement sur un shell cmd | `shell_disconnect_returns_error_on_cmd_shell` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Proxy injoignable : erreur | `invalid_proxy_returns_http_error` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |
| Builder, user agent personnalisé | `builder_pattern_works`, `custom_user_agent_does_not_break` | ✅ 2026-10-21 | ⏭ à mesurer (suite complète 2012 R2 en attente) | — non applicable |

Les tests de préparation du banc (`setup_https_listener`, `enable_credssp_server`,
`enable_cbt_hardening_strict` et assimilés) ne sont pas des fonctionnalités ; ils
ne figurent pas dans la matrice.

## Limites connues

- **Kerberos : chiffrement des messages par `gss_wrap`, mesuré sur un seul
  contrôleur.** Depuis `ac88145`, `EncryptionMode::Auto` scelle Kerberos sur
  HTTP (validé avec `AllowUnencrypted = false`) et `Always` le scelle dans
  HTTPS (vu sur le fil par le relais TLS). Limites : seuls les jetons
  RFC 4121 (CFX) sont acceptés, donc des clés AES ; un contexte RC4 échoue
  (un domaine RC4 seul doit passer à `EncryptionMode::Never`). Windows envoie
  toutes ses réponses Kerberos avec le numéro de séquence 0 et cross-krb5
  0.5.0 ne négocie ni détection de rejeu ni de séquence : la session
  Kerberos ne détecte aucun rejeu ; chaque réponse scellée doit nommer le
  `MessageID` de sa requête dans `RelatesTo` (une requête sans `MessageID`
  n'est pas envoyée), et une requête scellée rejouée par un attaquant actif
  sur la même connexion authentifiée n'est pas détectée. Sur HTTPS, le
  binding de canal est calculé pour le certificat vu par la sonde non
  authentifiée, puis ce certificat est épinglé dans le vérificateur de la
  connexion dédiée (`2bb6443`) : toute connexion suivante doit le
  présenter ; un certificat sans hachage de binding (Ed25519, algorithme
  inconnu) est refusé. L'épinglage vise le nom de serveur que `reqwest`
  transmet réellement (l'hôte de l'URL analysée : IDN en punycode, `10.1`
  en `10.0.0.1`, `win01?x` en `win01`) ; une fois épinglé, tout autre nom est
  refusé sauf la poignée de main propre au proxy `https://`, et un hôte sans
  nom de serveur TLS valide est refusé avant l'AP-REQ (`d13c982`).
  `EncryptionMode::Never` sur HTTP simple n'a rien de tout cela. Côté serveur,
  l'intégrité sur HTTP face à un attaquant actif suppose `AllowUnencrypted =
  false` (NTLM comme Kerberos). La branche SSPI de `cross-krb5` (client
  Windows) n'est ni compilée ici ni testée : un job CI `kerberos-windows`
  (check + clippy) l'ajoute, sans test ; sur un client Windows `Auto` scelle
  désormais, `EncryptionMode::Never` est le recours. L'hôte doit être le nom
  du serveur (SPN `HTTP/<hôte>`), pas une adresse ; le banc passe par une
  ligne `127.0.0.1 dc.winrm.test` dans `/etc/hosts`. Le port HTTPS `57986`
  du banc a été relayé le 2026-10-22 par un relais PowerShell non élevé sur
  la boucle locale (gsudo bloqué sur l'invite UAC), pas par le `netsh
  portproxy` décrit dans le README du banc.
- **Course du pool des connexions dédiées : atténuée, pas fermée.** `hyper`
  rend la connexion au pool du client depuis une tâche à lui ; une requête
  envoyée avant que cette tâche tourne part sur une connexion TCP neuve, non
  authentifiée, et échoue en HTTP 401 (fermé : erreur, pas de renvoi).
  L'échange cède la main 4 fois au runtime avant d'envoyer (nombre
  empirique, voir la ligne de la matrice). Le correctif déterministe,
  épingler une connexion `hyper` par connexion dédiée (`AuthConn`), demande
  un changement de `Cargo.toml` (hyper-util en dépendance directe) et n'est
  pas fait. Sur HTTPS (Kerberos `Auto`, connexion authentifiée une fois),
  la même mesure n'a montré aucun échec (40/40) ; une connexion perdue y
  ferait échouer la requête de la même façon (401, pas de renvoi).
- **Server 2012 R2 n'est mesuré qu'en partie.** La VM a été reconstruite ; à
  `92341f6`, `f30b7f3` puis `d69030d` seuls les tests NTLM (scellés sur HTTP, modes de chiffrement,
  proxy) et `create_and_delete_shell` / `run_command_whoami` y ont tourné
  (`vm-connect-2012r2.sh`, ports `56985`/`56986`) : tous passent, le format
  de trame scellée strict compris. La suite complète y reste à passer. Cinq
  tests y sont sautés
  volontairement : quatre tests HTTPS (`basic_over_https_works`,
  `ntlm_over_https_with_cbt`, `ntlm_encryption_always_over_https`,
  `credssp_run_command_whoami`), parce que le SCHANNEL
  de 2012 R2 n'associe GCM qu'à l'échange de clés RSA statique alors que
  `rustls` ne gère ni le RSA statique ni CBC, de sorte qu'aucune suite n'est
  commune et que la poignée de main se termine en EOF ; et
  `run_powershell_unicode`, parce que PowerShell 4.0 ignore
  `[Console]::OutputEncoding` sous `-EncodedCommand`.
- **Les tests à timeout court dépendent de la charge du serveur.** Ceux qui
  utilisent un `operation_timeout_secs` de 15 s (`shell_run_command_times_out`,
  `signal_terminate_stops_running_command`,
  `silent_command_longer_than_operation_timeout_completes` et les trois
  `silent_command_completes_over_*`) font aussi passer la
  création du shell dans cette fenêtre : sous un run entièrement parallèle sur un
  serveur chargé, elle peut la dépasser et échouer par `TimedOut` (reproduit
  avec 24 sessions PowerShell liées au CPU lancées en parallèle sur l'hôte :
  `Err(Soap(TimedOut))` de `open_shell` après environ 15 s). Depuis T19,
  `shell_run_command_times_out` et les tests de commande silencieuse
  réessayent une création ou un démarrage de commande échoué (6 créations et
  3 exécutions au plus pour le premier, 3 exécutions pour les autres) et
  signalent chaque échec s'ils n'obtiennent jamais de verdict ; l'assertion
  `Timeout(2 * 15)` et la borne de durée restent exactes. Sous une charge
  extrême, ils peuvent tout de même échouer. `--test-threads=1` les rend les
  plus fiables.
- **Les clés clientes chiffrées ne sont pas gérées.** `client_key_pem` doit être
  non chiffrée (`PRIVATE KEY`, `RSA PRIVATE KEY` ou `EC PRIVATE KEY`) ; une clé
  chiffrée est une `AuthFailed` à la construction.
- **Le même certificat client est présenté à tous les hôtes d'un client**, comme
  les identifiants appartiennent au client.
- **Un proxy `https://` partage la configuration d'authentification cliente** du
  transport.
- **Le crate ne fait confiance qu'aux racines webpki.** Il n'existe pas d'option
  pour une CA privée ; les CA internes poussent donc à `accept_invalid_certs`.
- **`WinrmClient::run_command` et `run_powershell` (donc aussi
  `download_file`) n'ont pas de délai total.** `operation_timeout_secs` borne
  chaque Receive, pas la commande. Depuis le correctif de D1, une commande
  bloquée et muette (`Read-Host`, `pause`, un processus bloqué) fait attendre
  l'appel jusqu'à sa fin au lieu d'échouer après environ
  `operation_timeout_secs` ; c'est un changement de comportement, documenté
  dans le `CHANGELOG` (`### Changed`) et la rustdoc. Remède :
  `run_command_with_cancel` / `run_powershell_with_cancel` ou
  `tokio::time::timeout` ; l'appel abandonné ne supprime pas le shell distant,
  que le serveur récupère après son idle timeout. `Shell::run_command` garde
  son délai total de `2 * operation_timeout_secs`. `run_wql` ne scrute pas
  Receive et n'est pas concerné.
- **Scellement NTLM et NTLM sur TLS : ce qui reste.** Les suites relevées
  par les audits sont traitées par `657570a`, `d95fe1c` et `62844d9` (repli
  en clair, Type 3 à corps vide, aucun renvoi d'une requête scellée, corps
  annoncé scellé non déchiffrable, session laissée en cache, contrôles de
  `unseal_body`, taille des réponses, cible de fuzz `fuzz_ntlm_unseal_body`,
  verrou global, jeton de liaison de canal (CBT) calculé sur le certificat
  de la connexion qui porte le défi, nouvelles tentatives limitées aux
  erreurs de connexion pour toutes les méthodes, au plus 32 échanges NTLM
  simultanés par client). Restent : `EncryptionMode::Never` envoie tout en
  clair sur HTTP (réservé au débogage) ; le comportement face à un serveur
  qui refuse le trafic non chiffré (`AllowUnencrypted = false`, réglage par
  défaut de Windows) n'a pas été mesuré, le banc l'autorise ; la cible de
  fuzz est compilée mais n'a pas tourné, et le `fuzz/Cargo.lock` est à
  rafraîchir ; un proxy HTTP qui transfère les requêtes (sans tunnel) sans
  garder une connexion serveur par connexion cliente casse la liaison NTLM à
  la connexion : les requêtes scellées échouent alors, sans partir en clair ;
  un 401 sur une connexion inactive que le serveur a fermée sans l'annoncer
  fait échouer la requête (`WinrmError::Ntlm`, « NOT resent ») au lieu de la
  renvoyer : `reqwest` n'expose pas l'adresse locale de la connexion qui a
  porté une réponse, donc un changement de socket ne se détecte pas avant ce
  401 (une réponse `Connection: close` fait déjà abandonner la connexion, et
  les connexions inactives depuis plus de 60 s ne sont pas réutilisées, sous
  le délai de 120 s de HTTP.sys) ; à travers un proxy, si le client d'une
  connexion NTLM a vu deux certificats différents, la poignée de main
  échoue (impossible de savoir lequel lier) ; une signature sans hachage
  unique (Ed25519) ou inconnue n'a pas de liaison de canal définie (RFC 5929)
  et fait échouer NTLM sur HTTPS (pypsrp, lui, retombe sur SHA-256) ;
  `unseal_body` est strict (Content-Type exact de la première partie, sans
  espace final ; `Length=` lu seulement sur la ligne `OriginalContent:`),
  ce que Server 2025 et 2012 R2 respectent ; les copies sur la pile de la
  clé de session faites par le constructeur du message Type 3, et la
  `NtlmSession` (clés, S-box RC4) construite sur la pile avant d'aller dans
  sa boîte, ne sont pas effacées.
- **NTLM et proxys.** Proxy HTTP `CONNECT` (HTTPS en tunnel) : la réponse ne
  porte pas les détails TLS (`reqwest` 0.13.5), le CBT vient du vérificateur
  du client dédié, restreint au nom du serveur WinRM ; testé en unitaire
  (`ntlm_cbt_binds_the_certificate_of_its_own_connection`) et en live pour
  Basic (`http_proxy_connect_carries_https`). Proxy SOCKS5 : même chemin ;
  live pour NTLM sur HTTP (`socks5_proxy_carries_ntlm`). Proxy `https://` :
  `reqwest` vérifie le certificat du proxy avec une copie de la même
  configuration TLS, ce certificat n'est pas compté (`d69030d`) ; testé en
  unitaire avec un proxy TLS en processus
  (`ntlm_cbt_through_an_https_proxy_binds_the_target_certificate`), pas en
  live (pas de proxy `https://` sur le banc). Proxy HTTP qui transfère sans
  tunnel : voir le point précédent (liaison NTLM à la connexion).
- **`bridge-mcp` (hors de ce dépôt, observation seulement).** Il n'interpole pas
  `${VAR}` alors que son `config.example.yaml` montre `${WIN_PASSWORD}` (la
  chaîne est envoyée telle quelle) et il convertit toute `AuthFailed` en
  « SSH authentication failed for unknown@WinRM », en perdant le message.
