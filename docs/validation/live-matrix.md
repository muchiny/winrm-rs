# Matrice de validation live de winrm-rs

Campagne du 2026-10-21, branche `test/live-coverage`. Chaque `✅` ci-dessous est
adossé à un test nommé qui a réellement passé contre une VM Windows ; rien n'est
déduit de la lecture du code.

## Commits testés

| Crate | Commit | Ce qui a été exécuté |
|---|---|---|
| `winrm-rs` | `d69030d` (branche `test/live-coverage`, dernier commit de code ou de test, après `3c6fdbf` qui ajoute les API `*_with_timeout` ; le commit de documentation qui le suit ne touche que le `CHANGELOG` et ce document ; les runs ci-dessous ont été faits sur cet arbre) | Suite live complète contre Server 2025 avec `--features credssp,__internal` (80 tests), les deux `eval` du banc faits : **80 passés, 0 échoué** (463 s) avec `--test-threads=1` ; en parallélisme par défaut, **80 passés, 0 échoué** (207 s ; `shell_run_command_times_out` reste sensible à la charge). Server 2012 R2 (VM reconstruite) : les tests NTLM et deux tests Basic seulement, voir « Limites connues ». Runs précédents : à `f30b7f3` et `92341f6`, 78 passés en série comme en parallèle ; à `4f229dc`, 78 passés en série, 77 passés et 1 échoué (`shell_run_command_times_out`) en parallèle ; à `4cbebfb`, 66 passés en série, 65 passés et 1 échoué en parallèle. Les tests à timeout court se lisent plus fiablement avec `--test-threads=1` (voir l'en-tête de `tests/integration_real.rs`). |
| `winrm-rs` (Kerberos) | `f8a1272` (code de production identique à `c46f8c6`), plus les tests Kerberos ajoutés par le commit qui suit | Contre le contrôleur de domaine `winrm.test` (banc séparé, `tests/vagrant/dc/README.md`), avec `--features kerberos` et un TGT obtenu par `kinit vagrant@WINRM.TEST` : `cargo test --features kerberos --test integration_real kerberos -- --ignored` → **3 passés, 0 échoué** (22 s). |
| `psrp-rs` | `4a79189` (`origin/main`) | Suite live (8 tests) contre le `winrm-rs` local (`[patch.crates-io]`, worktree jetable) : **8 passés, 0 échoué** contre `winrm-rs` `4cbebfb` (Basic), puis contre `84f1898` en Basic et en NTLM sur HTTP. Contre `winrm-rs` `4f229dc`, `92341f6`, `f30b7f3` puis `d69030d` (scellement qui échoue fermé et sans renvoi, une connexion authentifiée par échange, CBT de la connexion) : **8 passés** avec Basic sur HTTP (réglage par défaut de la suite) et **8 passés** avec `PSRP_INTEGRATION_AUTH=ntlm` (NTLM scellé sur HTTP), à chaque commit. Ce run NTLM, à travers un relais TCP enregistreur qui garde chaque connexion à part : 8 connexions (une par client), 2 requêtes `Negotiate` par connexion, 72 requêtes et 72 réponses `multipart/encrypted`, aucun corps de requête en clair (les Type 1 et Type 3 n'en portent pas), aucun HTTP 400 ni 500. |
| `bridge-mcp` | `f44a5fa` (v4.0.2, worktree jetable ; `origin/main` est maintenant `ec9310e`) | Smoke en ligne de commande par `winrm` puis par `psrp` (hôtes NTLM sur HTTP) : `hostname` renvoie `winrm-2025`, `Get-Date` renvoie la date du banc (2026-10-21), sur les deux protocoles. Fait contre `winrm-rs` `4cbebfb`, `84f1898`, `4f229dc`, `92341f6`, `f30b7f3`, puis `d69030d` (avec `psrp-rs` `4a79189`) : 4 appels sur 4 réussis à chaque fois (1,8 à 2,7 s chacun à `d69030d`), à travers le relais enregistreur : 4 connexions, 2 requêtes `Negotiate` par connexion, 26 requêtes scellées, aucun corps de requête en clair, aucun HTTP 400. Journal d'audit redirigé vers un fichier jetable. |

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
Trois tests Kerberos, sous `#[cfg(feature = "kerberos")]`, s'y ajoutent
(`kerberos_run_command_whoami`, `kerberos_two_commands_on_one_client`,
`silent_command_completes_over_kerberos`) ; ils visent le contrôleur de
domaine et ne font pas partie des runs complets contre Server 2025.

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
  complète fait 65/65 à `4cbebfb`.
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
  `4cbebfb`. L'hypothèse du plan (renégociation TLS que rustls ne gère pas) est
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
| `AuthMethod::Certificate` : certificat client présenté en TLS et mappé (après D2) | `setup_certificate_auth`, `certificate_auth_whoami` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `AuthMethod::Certificate` : certificat d'une CA non approuvée refusé en moins de 30 s | `certificate_auth_unmapped_cert_is_rejected` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Proxy HTTP réussi (forme absolue, NTLM sur HTTP) ; le trafic passe par le proxy, y compris pour `127.0.0.1` | `http_proxy_carries_ntlm_over_http` | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Proxy HTTP `CONNECT` portant du HTTPS | `http_proxy_connect_carries_https` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Proxy SOCKS5 | `socks5_proxy_carries_ntlm` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `max_output_bytes` déclenché, erreur `Transfer`, aucun shell laissé ouvert | `max_output_bytes_aborts_and_releases_shell` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `max_output_bytes` compte les octets bruts du stderr CLIXML | `max_output_bytes_counts_raw_clixml_stderr` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `connect_timeout_secs` respecté | `connect_timeout_is_honoured` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Délai total de `Shell::run_command` (`operation_timeout_secs * 2`) | `shell_run_command_times_out` (timeout d'opération de 15 s) | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Commande silencieuse plus longue que `operation_timeout_secs` menée à terme (après D1), Basic sur HTTP | `silent_command_longer_than_operation_timeout_completes` (20 s de silence, timeout d'opération de 15 s ; 22 à 25 s mesurées) | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Idem, NTLM sur HTTP avec scellement par défaut (après D1 et D3) | `silent_command_completes_over_ntlm_sealed_http` (relais enregistreur : 1 HTTP 500, 2 requêtes `Negotiate`, 6 requêtes scellées ; 21 à 25 s) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Idem, Certificate sur HTTPS (après D1 complété) | `silent_command_completes_over_certificate_auth` (24 s) | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Idem, CredSSP sur HTTPS (`--features credssp`, après D1 complété) | `silent_command_completes_over_credssp` (22 s) | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite (test sauté sur 2012 R2) | — non applicable |
| Idem, Kerberos sur HTTP (`--features kerberos`) | `silent_command_completes_over_kerberos` (22 s) | — non applicable (banc hors domaine) | ⏭ non mesuré : VM détruite | ✅ 2026-10-21 |
| Messages NTLM réellement scellés sur HTTP (après D3) | `silent_command_completes_over_ntlm_sealed_http` (requêtes `multipart/encrypted`, aucune réauthentification) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Transfert de 200 Ko aller-retour en NTLM scellé sur HTTP, contenu identique | `ntlm_sealed_upload_and_download_large_file` (101 morceaux ; 316 requêtes scellées, une seule poignée de main ; envoi 130 s, soit environ 1,3 s par morceau comme en Basic, réception 2,3 s, réponse la plus grosse 149 Ko) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Annulation (`run_command_with_cancel`) en NTLM scellé sur HTTP, puis le même client resservi | `ntlm_sealed_cancel_long_running_command` (annulation déclenchée une fois Execute et un premier Receive partis scellés : `Cancelled` ; la connexion de l'échange annulé est jetée, la commande suivante sur le même client ouvre une nouvelle connexion (4 requêtes `Negotiate` au total, 2 par connexion) et part scellée, aucun corps en clair) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Ctrl+C en NTLM scellé sur HTTP | `ntlm_sealed_shell_signal_ctrl_c` (5 requêtes scellées, une seule poignée de main) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| Shells concurrents sur un même client en NTLM scellé sur HTTP | `ntlm_sealed_concurrent_shells`, référence `concurrent_shells_timings_basic` (tous terminent ; un `echo` lancé pendant le Receive de 10 s de l'autre shell prend 0,19 s en NTLM scellé, contre 10,3 s avant `657570a` et 0,15 à 0,18 s en Basic ; le test exige moins de 3 s ; 2 connexions, une poignée de main chacune) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| 1,5 Mo de sortie en NTLM scellé, `MaxEnvelopeSize` par défaut puis 500 Ko | `ntlm_sealed_large_output_default_envelope`, `ntlm_sealed_large_output_500k_envelope` (sortie complète ; plus grosse réponse HTTP 149 Ko puis 155 Ko : Server 2025 plafonne un Receive vers 150 Ko même avec 500 Ko, bien sous le plafond de 2 Mio du client) | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| `EncryptionMode::Always` : NTLM scellé à l'intérieur de HTTPS | `ntlm_encryption_always_over_https` | ✅ 2026-10-21 | ⏭ sauté : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| API bas niveau : `create_shell`, `execute_command`, `receive_output`, `signal_terminate`, `delete_shell` | `low_level_command_lifecycle` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `signal_terminate` arrête une commande en cours | `signal_terminate_stops_running_command` (shell et commande créés avec un client au timeout par défaut ; scrutation, arrêt et vidage avec un timeout d'opération de 15 s) | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `open_psrp_shell` | psrp-rs (`4a79189`) : les 8 tests live, dont `live_smoke_one_plus_one` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `start_command_with_id` | psrp-rs : les 8 tests live (chaque pipeline passe par lui) | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `Shell::disconnect` réussi | psrp-rs : `live_disconnect_reconnect_pool` seul (la déconnexion a réellement eu lieu, sans le message « disconnect not supported ») | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `reconnect_shell` | psrp-rs : `live_disconnect_reconnect_pool` seul | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Chaîne complète `bridge-mcp` (`hostname`, `Get-Date`) par `winrm` et par `psrp` | smoke CLI `bridge-mcp` `f44a5fa` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `AuthMethod::Kerberos` sur HTTP (`--features kerberos`, TGT de `kinit`) : la commande tourne sous le compte du domaine | `kerberos_run_command_whoami` (`winrm\vagrant`), `kerberos_two_commands_on_one_client` (deux commandes sur le même client) ; observé avec `KRB5_TRACE` (AP-REP vérifié), sans assertion nommée | — non applicable (banc hors domaine) | ⏭ non mesuré : VM détruite | ✅ 2026-10-21 |
| Doc de `AuthMethod::CredSsp` (disait « Not yet implemented ») | relue contre `credssp_run_command_whoami` | doc corrigée le 2026-10-21 (relecture ; le passage live est la ligne CredSSP plus bas) | ⏭ non mesuré : VM détruite | — non applicable |

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
| Basic sur HTTPS | `basic_over_https_works` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| NTLM sur HTTP | `ntlm_run_command_whoami`, `ntlm_run_powershell`, `ntlm_shell_reuse` | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| NTLM sur HTTPS avec channel binding (CBT) | `ntlm_over_https_with_cbt` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Les trois `EncryptionMode` (ces tests passaient aussi avant D3 grâce au repli en clair : ils ne prouvent pas le scellement, voir la ligne « Messages NTLM réellement scellés ») | `ntlm_encryption_always`, `ntlm_encryption_never`, `ntlm_encryption_auto_over_http` | ✅ 2026-10-21 | ✅ 2026-10-21 (VM reconstruite) | — non applicable |
| CredSSP (`--features credssp`) | `credssp_run_command_whoami` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite (test sauté sur 2012 R2 : voir « Limites connues ») | — non applicable |
| PowerShell, JSON, Unicode | `run_powershell_version`, `run_powershell_json_output`, `run_powershell_unicode`, `gather_host_facts_json` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Réutilisation d'un shell, démarrage et lecture manuels | `shell_reuse_multiple_commands`, `shell_start_command_and_receive` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| stdin | `shell_send_input_stdin` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Ctrl+C | `shell_signal_ctrl_c` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Annulation | `cancel_long_running_command`, `shell_run_powershell_with_cancel` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Idle timeout | `shell_with_idle_timeout_works` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Répertoire de travail | `shell_with_working_directory` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Variables d'environnement | `shell_with_env_vars` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Transferts de fichiers | `upload_and_download_file`, `upload_and_download_large_file`, `upload_and_download_binary_file` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| WQL | `wql_query_win32_operatingsystem`, `wql_query_win32_service`, `wql_query_custom_namespace`, `wql_query_invalid_namespace` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `max_envelope_size` réduit | `small_max_envelope_size` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Retries | `retry_config_works_with_real_server` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Shells concurrents | `concurrent_shells` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| stderr CLIXML décodé (petit, gros, en flux) | `powershell_stderr_clixml_parsed`, `powershell_large_clixml_stderr_reassembled`, `streaming_large_clixml_stderr_reassembled` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Erreurs sur identifiants de shell invalides | `invalid_shell_id_returns_error`, `double_delete_shell_returns_error`, `command_on_deleted_shell_returns_error` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| `Shell::disconnect` refusé proprement sur un shell cmd | `shell_disconnect_returns_error_on_cmd_shell` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Proxy injoignable : erreur | `invalid_proxy_returns_http_error` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |
| Builder, user agent personnalisé | `builder_pattern_works`, `custom_user_agent_does_not_break` | ✅ 2026-10-21 | ⏭ non mesuré : VM détruite | — non applicable |

Les tests de préparation du banc (`setup_https_listener`, `enable_credssp_server`,
`enable_cbt_hardening_strict` et assimilés) ne sont pas des fonctionnalités ; ils
ne figurent pas dans la matrice.

## Limites connues

- **Kerberos : validé sur HTTP seulement, et sans chiffrement des messages.**
  Les trois tests Kerberos passent contre le contrôleur de domaine
  `winrm.test`, mais le corps SOAP part en clair : le crate n'a pas de
  chiffrement Kerberos des messages et `EncryptionMode` ne s'applique qu'à
  NTLM. Le serveur doit donc autoriser le trafic non chiffré
  (`AllowUnencrypted = true`, posé par le `Vagrantfile` du banc) ; avec
  `AllowUnencrypted = false`, mesuré le 2026-10-21, chaque requête échoue en
  `AuthFailed("HTTP 500 Internal Server Error: ")`, un message qui ne dit pas
  pourquoi. Kerberos sur HTTPS n'a pas été mesuré (pas d'écouteur HTTPS sur le
  contrôleur de domaine). L'hôte doit être le nom du serveur (le SPN
  `HTTP/<hôte>` en est dérivé), pas une adresse ; le banc passe par une ligne
  `127.0.0.1 dc.winrm.test` dans `/etc/hosts`.
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
  serveur chargé, elle peut la dépasser et échouer par `TimedOut`.
  `--test-threads=1` les rend les plus fiables.
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
