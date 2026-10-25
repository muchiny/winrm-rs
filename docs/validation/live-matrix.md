# Matrice de validation live de winrm-rs

Campagne du 2026-10-21, branche `test/live-coverage`. Chaque `✅` ci-dessous est
adossé à un test nommé qui a réellement passé contre une VM Windows ; rien n'est
déduit de la lecture du code.

## Commits testés

| Crate | Commit | Ce qui a été exécuté |
|---|---|---|
| `winrm-rs` | `2ab43dc` (branche `test/live-coverage`, dernier commit de la branche avant la mise à jour de cette matrice ; tous les commits de code et de test venus après `0e61241` y sont rejoués en live : refus d'un hôte qui n'est pas un nom d'hôte, nouvelles tentatives de création de shell dans les tests à timeout court, `tokio` 1.54.1, correctifs de la revue finale (journaux sans identifiants, en-têtes `Authorization` sensibles, extraction d'éléments linéaire, proxys `https://` de l'environnement admis par le vérificateur épinglé, erreurs bornées), garde des corps chunked du relais enregistreur ; le commit qui met cette matrice à jour ne touche pas au code). Avant : `0e61241` (troisième tour de correctifs de l'épinglage du certificat Kerberos), puis Avant : `f43bfb0` (dernier commit de code ou de test, après `31a02eb` qui ajoute les API `*_with_timeout` ; le commit de documentation qui le suit ne touche que le `CHANGELOG` et ce document ; les runs à 80 tests ont été faits sur cet arbre) | Suite live complète contre Server 2025 avec `--features credssp,__internal` (81 tests, variables du banc exportées à la main, `vm-connect.sh` restant bloqué sur gsudo), les deux `eval` du banc faits (`make-client-cert.sh` compris), à `2ab43dc` : **81 passés, 0 échoué** (212 s) en parallélisme par défaut ; **81 passés, 0 échoué** (470 s) avec `--test-threads=1`. Aucun test sauté, aucun échec à relancer. Runs précédents : à `0e61241`, 81 passés, 0 échoué (218 s, parallélisme par défaut) ; à `d6aeb2c` : 81 passés (213 s) ; à `3759367` : 81 passés (209 s) ; à `c0f0d2e` : 81 passés (213 s). À `f43bfb0` : suite live complète contre Server 2025 avec `--features credssp,__internal` (80 tests), les deux `eval` du banc faits : **80 passés, 0 échoué** (463 s) avec `--test-threads=1` ; en parallélisme par défaut, **80 passés, 0 échoué** (207 s ; `shell_run_command_times_out` reste sensible à la charge). Server 2012 R2 (VM reconstruite, évaluation 6.3.9600, PowerShell 4.0), suite complète à `64c4a0b` avec `--features credssp,__internal` (81 tests, `vm-connect-2012r2.sh` et `make-client-cert.sh` évalués) : **81 passés, 0 échoué, dont 12 sautés par garde `is_server_2012_r2()`** (donc 69 réellement exécutés, voir « Limites connues ») en 212 s avec `--test-threads=1` et en 33 s en parallélisme par défaut. Un premier run à `d515b88` avait 6 échecs, tous déterministes (relancés 3 fois chacun) et tous des limites de 2012 R2, d'où les 6 gardes ajoutées par `64c4a0b`. Les 13 tests Kerberos ne font pas partie de ce run (pas de KDC). Runs précédents : à `824128c` et `f82af53`, 78 passés en série comme en parallèle ; à `fcfdffc`, 78 passés en série, 77 passés et 1 échoué (`shell_run_command_times_out`) en parallèle ; à `a19c202`, 66 passés en série, 65 passés et 1 échoué en parallèle. Les tests à timeout court se lisent plus fiablement avec `--test-threads=1` (voir l'en-tête de `tests/integration_real.rs`). |
| `winrm-rs` (Kerberos) | `2ab43dc` : les trois groupes `kerberos` (7 passés), `allow_unencrypted_false` (3 passés) et `dc_cbt` (2 passés) rejoués à ce commit. Avant : `0e61241` (troisième tour : cible du vérificateur prise de l'URL analysée, épinglage refusé sans cible, tout autre nom refusé une fois épinglé ; avant lui `d6aeb2c`, certificat épinglé après la sonde) ; groupes `kerberos` (7 passés) et `dc_cbt` (2 passés) rejoués à `0e61241`, le groupe `allow_unencrypted_false` à `d6aeb2c` (code TLS seul changé depuis) | Contre le contrôleur de domaine `winrm.test` (banc séparé, `tests/vagrant/dc/README.md`), avec `--features kerberos` et un TGT obtenu par `kinit vagrant@WINRM.TEST`, le 2026-10-22, à `2ab43dc` (écouteur HTTPS déjà en place, `setup_dc_https_listener` non rejoué) : `... kerberos -- --ignored --skip allow_unencrypted_false --skip dc_cbt` → **7 passés, 0 échoué** (22 s) ; `... allow_unencrypted_false -- --ignored --test-threads=1` → **3 passés, 0 échoué** (304 s ; `AllowUnencrypted` remis à `true` après chacun) ; `... dc_cbt -- --ignored --test-threads=1` → **2 passés, 0 échoué** (15 s ; `CbtHardeningLevel` remis à `Relaxed` après chacun). État final du contrôleur vérifié par une requête NTLM scellée : `AllowUnencrypted = true`, `CbtHardeningLevel = Relaxed`. Mêmes comptes à `0e61241` (7 + 2, `allow_unencrypted_false` à `d6aeb2c` : 3 passés en 298 s). Runs précédents : `3759367` (6 + 3 + 2 passés, sans épinglage) ; `c53acbe`/`1967dbf` (5 + 2 passés, sans binding de canal) ; `f4827bb`, 3 passés sur HTTP sans chiffrement. |
| `psrp-rs` | `4a79189` (`origin/main`) ; rejoué contre `winrm-rs` `2ab43dc` | Suite live (8 tests) contre le `winrm-rs` local (`[patch.crates-io]`, worktree jetable) : **8 passés, 0 échoué** contre `winrm-rs` `a19c202` (Basic), puis contre `83a71c3` en Basic et en NTLM sur HTTP. Contre `winrm-rs` `fcfdffc`, `f82af53`, `824128c`, `f43bfb0` puis `2ab43dc` (scellement qui échoue fermé et sans renvoi, une connexion authentifiée par échange, CBT de la connexion ; Kerberos scellé, épinglage et correctifs de revue pour le dernier) : **8 passés** avec Basic sur HTTP (réglage par défaut de la suite ; 8,2 s à `2ab43dc`) et **8 passés** avec `PSRP_INTEGRATION_AUTH=ntlm` (NTLM scellé sur HTTP ; 8,6 s à `2ab43dc`), à chaque commit. Le run NTLM, identique à `f43bfb0` et à `2ab43dc`, à travers un relais TCP enregistreur qui garde chaque connexion à part : 8 connexions (une par client), 2 requêtes `Negotiate` par connexion, 72 requêtes et 72 réponses `multipart/encrypted`, aucun corps de requête en clair (les Type 1 et Type 3 n'en portent pas), aucun HTTP 400 ni 500. |
| `bridge-mcp` | `f44a5fa` (v4.0.2, worktree jetable ; `origin/main` est maintenant `ec9310e`, v4.1.0, non testé) ; rejoué contre `winrm-rs` `2ab43dc` | Smoke en ligne de commande par `winrm` puis par `psrp` (hôtes NTLM sur HTTP) : `hostname` renvoie `winrm-2025`, `Get-Date` renvoie la date du banc (2026-10-21, puis 2026-10-22 à `2ab43dc`), sur les deux protocoles. Fait contre `winrm-rs` `a19c202`, `83a71c3`, `fcfdffc`, `f82af53`, `824128c`, `f43bfb0` puis `2ab43dc` (avec `psrp-rs` `4a79189`) : 4 appels sur 4 réussis à chaque fois (1,8 à 2,7 s chacun à `f43bfb0`, 1,8 à 2,6 s à `2ab43dc`), à travers le relais enregistreur : 4 connexions, 2 requêtes `Negotiate` par connexion, 26 requêtes scellées, aucun corps de requête en clair, aucun HTTP 400. Journal d'audit redirigé vers un fichier jetable. |

Banc : une VM Windows Server 2025 (`winrm-2025`) sous Hyper-V, atteinte par
`tests/scripts/vm-connect.sh` (HTTP `55985`, HTTPS `55986`, compte `vagrant`).
Kerberos : une seconde VM, contrôleur de domaine Windows Server 2025 de la
forêt `winrm.test` (VM Hyper-V `winrm-rs-dc`, hôte `dc`), atteinte par
`tests/scripts/vm-connect-dc.sh` (WinRM HTTP `57985`, KDC TCP `57088`, compte
`WINRM\vagrant`) ; voir `tests/vagrant/dc/README.md`.
Au départ de la campagne (avant tout ajout de test), les 52 tests live
existants passaient : 52 passés, 0 échoué, 0 sauté (sans la feature `credssp`).

Les tests ajoutés par la campagne portent le total à 80 sans feature, ou 82
avec la feature `credssp` (`credssp_run_command_whoami` et
`silent_command_completes_over_credssp` sont sous `#[cfg(feature =
"credssp")]`), et à 95 avec les 13 tests Kerberos (compte des fonctions
`#[ignore]` de `tests/integration_real.rs` par attribut `cfg`) : 13 jusqu'à
`a19c202`, 3 avec `eddd4f6` (une commande silencieuse par méthode
d'authentification live, dont celle de CredSSP), 5 avec `83a71c3`
(transferts, annulation, Ctrl+C et shells concurrents en NTLM scellé, plus
la référence Basic des shells concurrents), 1 avec `d7dde44`
(`streaming_clixml_stderr_yields_records_before_exit`), 3 avec `fcfdffc`
(1,5 Mo de sortie en NTLM scellé avec deux `MaxEnvelopeSize`,
`EncryptionMode::Always` sur HTTPS), puis 3 avec les API à délai total et
l'annulation qui libère le shell (`run_powershell_with_timeout_expires_and_releases_shell`,
`run_powershell_with_timeout_returns_output_of_a_fast_command`,
`run_powershell_with_cancel_releases_shell`), puis 1 avec `d3bf664`
(`write_host_reaches_stdout_once`). Les runs complets à `0e61241` et à `2ab43dc`
exécutent tous les autres (81 avec `credssp`) ; `write_host_reaches_stdout_once`
a été lancé seul, le 2026-10-22 à `d3bf664`, contre Server 2025 et Server 2012 R2.
Les tests Kerberos, sous `#[cfg(feature = "kerberos")]`, s'y ajoutent
(`kerberos_run_command_whoami`, `kerberos_two_commands_on_one_client`,
`silent_command_completes_over_kerberos`, puis avec `1967dbf`
`kerberos_over_https_whoami`, `kerberos_encryption_always_over_https`,
`kerberos_sealed_with_allow_unencrypted_false`,
`kerberos_unsealed_with_allow_unencrypted_false_is_a_clear_error` et la
préparation `setup_dc_https_listener`, puis avec `8efff28`, `3759367` et `d6aeb2c`
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
  `4362934`, par exemple `git worktree add <dossier> 4362934`, banc 2025
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
- **Commits qui corrigent.** `664bfec` (correctif : le fault `TimedOut` sur
  Receive devient une scrutation vide), puis les tests durcis par `3a10101`,
  `2b6be1b` et `26511ff` (les trois tests concernés passent à un timeout
  d'opération de 15 s, plus un test de régression sur le décodeur CLIXML coupé
  par une scrutation `TimedOut`).
- **Vérifié après correctif.** Les trois tests live concernés passent
  (`signal_terminate_stops_running_command`, `shell_run_command_times_out`,
  `silent_command_longer_than_operation_timeout_completes`) et la suite
  complète fait 65/65 à `a19c202` (sans la feature `credssp`).
- **Complément (après `a19c202`) : le correctif n'atteignait que Basic et NTLM non
  scellé.** Certificate, Kerberos et CredSSP rendaient un HTTP 500 portant un
  fault SOAP comme `AuthFailed`, de sorte que le `TimedOut` n'arrivait jamais
  au traitement « scrutation vide ». Reproduction : dans un checkout de
  `eddd4f6`, remettre les sources d'avant (`git checkout 612111a -- src/`) et
  lancer `cargo test --features credssp,__internal --test integration_real --
  --ignored silent_command` (avec les deux `eval` du banc) :
  `silent_command_completes_over_certificate_auth` échoue sur
  `AuthFailed("Certificate auth HTTP 500 Internal Server Error: <s:Envelope …
  w:TimedOut …")` et `silent_command_completes_over_credssp` sur
  `AuthFailed("CredSSP HTTP 500: …")`. Corrigé par `de4f9ac` (un seul mappage
  statut vers erreur, `auth::error_for_status`, pour les six points d'appel).
  Vérifié live : une commande silencieuse 20 s avec un timeout d'opération de
  15 s se termine en Basic, NTLM scellé sur HTTP, Certificate et CredSSP.
  Kerberos, vérifié ensuite contre le contrôleur de domaine `winrm.test` :
  `silent_command_completes_over_kerberos` passe (22 s).

### D3 : le scellement NTLM sur HTTP ne fonctionnait pas, tout repartait en clair

- **Trouvé en mesurant D1 sur NTLM sur HTTP** (configuration par défaut,
  `EncryptionMode::Auto`). Reproduction : dans un checkout de `eddd4f6`,
  `git checkout 612111a -- src/`, puis
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
- **Commits qui corrigent.** `1291e59` (format MIME aligné sur ce que Windows
  envoie et ce que pypsrp construit) et `9e61b9f` (déchiffrer un HTTP 500
  scellé avant d'y chercher le fault ; la session scellée est conservée).
- **Vérifié après correctif.** `silent_command_completes_over_ntlm_sealed_http`
  passe à travers un relais TCP qui enregistre le trafic : 1 réponse HTTP 500
  (le `TimedOut`), 2 requêtes `Negotiate` (une seule poignée de main), 6
  requêtes `multipart/encrypted`. Les tests `ntlm_*` passent, ainsi que les
  tests `ntlm_sealed_*` ajoutés ensuite (transferts, annulation, Ctrl+C,
  shells concurrents en NTLM scellé), la suite live de `psrp-rs` en NTLM sur
  HTTP et le smoke `bridge-mcp` (lignes « Commits testés »).
- **Fermé ensuite (`74578d2`) : le repli en clair et le verrou global.** Les
  correctifs ci-dessus laissaient deux chemins en clair (le corps SOAP porté
  par la requête Type 3, et toute requête scellée en échec rejouée en clair
  après une nouvelle poignée de main, donc exécutable deux fois) et un verrou
  tenu pendant tout l'échange. Désormais : Type 3 à corps vide ; aucune
  requête scellée n'est renvoyée, pas même sur un 401 (`ad908b3` : un
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

- **Reproduction, au commit avant le correctif** (checkout de `4362934`, banc
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
- **Commits qui corrigent.** `c2a23cc` (présenter le certificat et l'en-tête
  `Authorization`), puis `a19c202` (durcissement : lecture bornée des fichiers
  PEM, `Certificate` sur HTTP en clair devient une `AuthFailed` à la
  construction, message dédié pour une clé chiffrée, test certificat + clé dans
  un seul fichier, test mTLS en processus qui ne dépend plus de l'environnement
  proxy).
- **Vérifié après correctif.** `certificate_auth_whoami` renvoie le compte
  mappé, `certificate_auth_unmapped_cert_is_rejected` reçoit 401 pour un
  certificat d'une CA non approuvée, et la suite complète fait 65/65 à
  `a19c202` (sans la feature `credssp`). L'hypothèse du plan (renégociation TLS que rustls ne gère pas) est
  réfutée : avec `clientcertnegotiation=enable`, le serveur envoie le
  `CertificateRequest` dans la poignée de main initiale.
- **État laissé sur le banc 2025** (par `setup_certificate_auth`, idempotent) :
  la CA de test dans `Root` et `TrustedPeople`, `Auth\Certificate` activé, un
  mappage de certificat client, `clientcertnegotiation` activé sur
  `0.0.0.0:5986`.

Historique complet des commits de la branche : `git log --oneline
252c555..test/live-coverage` (`252c555` est la fusion de la PR #3 sur `main`,
base de la branche). Les quatre premiers commits de cette plage (le
rafraîchissement de `fuzz/Cargo.lock`, le décodeur CLIXML en flux, le
réassemblage du stderr CLIXML entre scrutations, la cible de fuzz et les
proptests qui vont avec) viennent de l'instantané de travail de
l'utilisateur, scindé avant publication, et sont hors de cette campagne.

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
| `AuthMethod::Certificate` : certificat client présenté en TLS et mappé (après D2) | `setup_certificate_auth`, `certificate_auth_whoami` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls, et `netsh http update sslcert … clientcertnegotiation` n'existe pas sur cette version (voir « Limites connues ») | — non applicable |
| `AuthMethod::Certificate` : certificat d'une CA non approuvée refusé en moins de 30 s | `certificate_auth_unmapped_cert_is_rejected` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : même cause que la ligne précédente (voir « Limites connues ») | — non applicable |
| Proxy HTTP réussi (forme absolue, NTLM sur HTTP) ; le trafic passe par le proxy, y compris pour `127.0.0.1` | `http_proxy_carries_ntlm_over_http` | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| Proxy HTTP `CONNECT` portant du HTTPS | `http_proxy_connect_carries_https` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| Proxy SOCKS5 | `socks5_proxy_carries_ntlm` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| `max_output_bytes` déclenché, erreur `Transfer`, aucun shell laissé ouvert | `max_output_bytes_aborts_and_releases_shell` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| `max_output_bytes` compte les octets bruts du stderr CLIXML | `max_output_bytes_counts_raw_clixml_stderr` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : PowerShell 4.0 rend un `Write-Error` bien plus gros (91 Ko décodés pour 40 erreurs), la précondition du test ne tient pas (voir « Limites connues ») | — non applicable |
| `run_powershell_with_timeout` : délai total atteint, `Timeout(8)` rendu entre 8 et 15 s, shell distant supprimé | `run_powershell_with_timeout_expires_and_releases_shell` (`Start-Sleep 600` ; shells comptés par un `IdleTimeOut` marqueur, avec témoin positif) | ✅ 2026-10-22 | ✅ 2026-10-22 | — non applicable |
| `run_powershell_with_timeout` : une commande rapide rend sa sortie et son code de sortie, aucun shell laissé | `run_powershell_with_timeout_returns_output_of_a_fast_command` | ✅ 2026-10-22 | ✅ 2026-10-22 | — non applicable |
| `run_powershell_with_cancel` : `Cancelled` rendu en moins de 10 s, terminaison et suppression du shell envoyées, aucun shell laissé | `run_powershell_with_cancel_releases_shell` (annulation après 3 s d'un `Start-Sleep 600`) | ✅ 2026-10-22 | ✅ 2026-10-22 | — non applicable |
| stderr CLIXML en flux : les enregistrements vidés tôt arrivent à `receive_next` avant la fin de la commande | `streaming_clixml_stderr_yields_records_before_exit` | ✅ 2026-10-22 | ✅ 2026-10-22 | — non applicable |
| Texte de `Write-Host` sur stdout, une seule fois : sa copie en enregistrement information du stderr CLIXML est écartée au décodage (soulevé par #1) | `write_host_reaches_stdout_once` (vérifie aussi, sur le stderr brut de `receive_output_raw`, que la copie existe) | ✅ 2026-10-22 | ✅ 2026-10-22 (moitié stdout et stderr décodé ; moitié brute sautée : PowerShell 4.0 n'a pas de flux information, stderr brut vide pour un `Write-Host` seul) | — non applicable |
| `connect_timeout_secs` respecté | `connect_timeout_is_honoured` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Délai total de `Shell::run_command` (`operation_timeout_secs * 2`) | `shell_run_command_times_out` (timeout d'opération de 15 s) | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Commande silencieuse plus longue que `operation_timeout_secs` menée à terme (après D1), Basic sur HTTP | `silent_command_longer_than_operation_timeout_completes` (20 s de silence, timeout d'opération de 15 s ; 22 à 25 s mesurées) | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Idem, NTLM sur HTTP avec scellement par défaut (après D1 et D3) | `silent_command_completes_over_ntlm_sealed_http` (relais enregistreur : 1 HTTP 500, 2 requêtes `Negotiate`, 6 requêtes scellées ; 21 à 25 s) | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| Idem, Certificate sur HTTPS (après D1 complété) | `silent_command_completes_over_certificate_auth` (24 s) | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| Idem, CredSSP sur HTTPS (`--features credssp`, après D1 complété) | `silent_command_completes_over_credssp` (22 s) | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| Idem, Kerberos sur HTTP (`--features kerberos`), scellé par défaut depuis `c53acbe` | `silent_command_completes_over_kerberos` (22 s ; en clair le 2026-10-21, scellé le 2026-10-22) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Messages NTLM réellement scellés sur HTTP (après D3) | `silent_command_completes_over_ntlm_sealed_http` (requêtes `multipart/encrypted`, aucune réauthentification) | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| Transfert de 200 Ko aller-retour en NTLM scellé sur HTTP, contenu identique | `ntlm_sealed_upload_and_download_large_file` (101 morceaux ; 316 requêtes scellées, une seule poignée de main ; envoi 130 s, soit environ 1,3 s par morceau comme en Basic, réception 2,3 s, réponse la plus grosse 149 Ko) | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| Annulation (`run_command_with_cancel`) en NTLM scellé sur HTTP, puis le même client resservi | `ntlm_sealed_cancel_long_running_command` (annulation déclenchée une fois Execute et un premier Receive partis scellés : `Cancelled` ; la connexion de l'échange annulé est jetée, la commande suivante sur le même client ouvre une nouvelle connexion (4 requêtes `Negotiate` au total, 2 par connexion) et part scellée, aucun corps en clair) | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| Ctrl+C en NTLM scellé sur HTTP | `ntlm_sealed_shell_signal_ctrl_c` (5 requêtes scellées, une seule poignée de main) | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| Shells concurrents sur un même client en NTLM scellé sur HTTP | `ntlm_sealed_concurrent_shells`, référence `concurrent_shells_timings_basic` (tous terminent ; un `echo` lancé pendant le Receive de 10 s de l'autre shell prend 0,19 s en NTLM scellé, contre 10,3 s avant `74578d2` et 0,15 à 0,18 s en Basic ; le test exige moins de 3 s ; 2 connexions, une poignée de main chacune) | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| 1,5 Mo de sortie en NTLM scellé, `MaxEnvelopeSize` par défaut puis 500 Ko | `ntlm_sealed_large_output_default_envelope`, `ntlm_sealed_large_output_500k_envelope` (sortie complète ; plus grosse réponse HTTP 149 Ko puis 155 Ko : Server 2025 plafonne un Receive vers 150 Ko même avec 500 Ko, bien sous le plafond de 2 Mio du client) | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| `EncryptionMode::Always` sur HTTPS en NTLM : accepté par le serveur | `ntlm_encryption_always_over_https` (prouve seulement que le serveur accepte l'échange ; que les corps partent bien scellés dans TLS est vu sur le fil par `always_seals_inside_tls_seen_by_a_relay_with_dc_cbt_none`, ligne « `EncryptionMode::Always` : Kerberos et NTLM scellés à l'intérieur de HTTPS » plus bas) | ✅ 2026-10-21 | ⏭ sauté : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| API bas niveau : `create_shell`, `execute_command`, `receive_output`, `signal_terminate`, `delete_shell` | `low_level_command_lifecycle` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| `signal_terminate` arrête une commande en cours | `signal_terminate_stops_running_command` (shell et commande créés avec un client au timeout par défaut ; scrutation, arrêt et vidage avec un timeout d'opération de 15 s) | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| `open_psrp_shell` | psrp-rs (`4a79189`) : les 8 tests live, dont `live_smoke_one_plus_one` | ✅ 2026-10-21 | ⏭ non mesuré : `psrp-rs` n'a pas été lancé contre cette VM | — non applicable |
| `start_command_with_id` | psrp-rs : les 8 tests live (chaque pipeline passe par lui) | ✅ 2026-10-21 | ⏭ non mesuré : `psrp-rs` n'a pas été lancé contre cette VM | — non applicable |
| `Shell::disconnect` réussi | psrp-rs : `live_disconnect_reconnect_pool` seul (la déconnexion a réellement eu lieu, sans le message « disconnect not supported ») | ✅ 2026-10-21 | ⏭ non mesuré : `psrp-rs` n'a pas été lancé contre cette VM | — non applicable |
| `reconnect_shell` | psrp-rs : `live_disconnect_reconnect_pool` seul | ✅ 2026-10-21 | ⏭ non mesuré : `psrp-rs` n'a pas été lancé contre cette VM | — non applicable |
| Chaîne complète `bridge-mcp` (`hostname`, `Get-Date`) par `winrm` et par `psrp` | smoke CLI `bridge-mcp` `f44a5fa` | ✅ 2026-10-21 | ⏭ non mesuré : `bridge-mcp` n'a pas été lancé contre cette VM | — non applicable |
| `AuthMethod::Kerberos` sur HTTP (`--features kerberos`, TGT de `kinit`) : la commande tourne sous le compte du domaine ; messages scellés par défaut depuis `c53acbe` | `kerberos_run_command_whoami` (`winrm\vagrant`), `kerberos_two_commands_on_one_client` (deux commandes sur le même client) ; AP-REP vérifié : le scellement exige le jeton du serveur pour établir le contexte | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Kerberos sur HTTPS (écouteur HTTPS du contrôleur, certificat auto-signé, `accept_invalid_certs`) | `kerberos_over_https_whoami` (passé sans changement de code à `c1b1e14` et `c53acbe`, sans binding de canal ; depuis `38a42b2` une connexion dédiée authentifiée une fois, binding de canal et AP-REP exigé, passé à `3759367`) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Chiffrement des messages Kerberos sur HTTP avec `AllowUnencrypted = false` (serveur qui l'exige) | `kerberos_sealed_with_allow_unencrypted_false` (relais enregistreur : `whoami` ; transfert de 200 Ko aller-retour identique, 323 requêtes dont 322 scellées, 1 connexion, 1 requête `Negotiate`, aucun corps en clair ; commande silencieuse de 21 s dont les fautes `TimedOut` reviennent scellées en HTTP 500) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| `EncryptionMode::Always` : Kerberos et NTLM scellés à l'intérieur de HTTPS, vu sur le fil | `always_seals_inside_tls_seen_by_a_relay_with_dc_cbt_none` (relais TLS qui termine TLS, `CbtHardeningLevel = None` le temps du test : Kerberos `Always` 5 corps sur 5 scellés, Kerberos `Auto` 0 sur 5, NTLM `Always` 5 sur 5) ; `kerberos_encryption_always_over_https` seul ne prouve que l'acceptation par le serveur | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Kerberos non chiffré (`EncryptionMode::Never`) refusé par `AllowUnencrypted = false` : erreur claire | `kerberos_unsealed_with_allow_unencrypted_false_is_a_clear_error` (HTTP 500 au corps vide ; le message nomme `AllowUnencrypted` et les remèdes ; avant `c53acbe` : `AuthFailed("HTTP 500 Internal Server Error: ")`) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Binding de canal Kerberos sur HTTPS (RFC 5929 `tls-server-end-point`) | `kerberos_channel_binding_through_a_tls_relay_is_refused` (relais TLS présentant son propre certificat : refusé sous `Relaxed`, `Auto` et `Always`, aucun corps SOAP n'atteint le relais) ; `kerberos_over_https_with_dc_cbt_strict` (`Strict` : `Auto` et `Always` en direct passent, le relais est refusé) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Binding de canal Kerberos : cas scindé (la sonde passe intacte jusqu'au contrôleur, la connexion suivante est terminée par un relais avec un autre certificat) | `kerberos_channel_binding_split_relay_fails_at_the_handshake` (`Auto` et `Always` : la poignée de main TLS de la connexion de l'AP-REQ est refusée par le vérificateur épinglé, le relais ne reçoit aucune requête ; avant `b1f5d7f` l'AP-REQ atteignait le relais) ; rejoué sous `Strict` dans `kerberos_over_https_with_dc_cbt_strict` | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 |
| Kerberos sur HTTPS (`Auto`, connexion authentifiée une fois) : requêtes suivantes restées sur la connexion authentifiée | aucun test nommé ; mesure ad hoc du 2026-10-22 : envoi de 20 Ko puis téléchargement de 200 Ko sur HTTPS, 10 essais par case, runtime current-thread et multi-thread, 0 et 4 cessions de main : 10/10 partout, exactement 2 connexions TCP par essai (la sonde, puis la connexion authentifiée) | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ⏭ pas de test nommé (mesure ad hoc concluante, voir « Tests ») |
| Course du pool des connexions dédiées (requête scellée partie sur une connexion TCP neuve non authentifiée) | `sealed_download_after_upload_stays_on_its_connection_allow_unencrypted_false` (3 tours Kerberos + 3 tours NTLM, chacun sur une seule connexion) ; mesure ad hoc, `AllowUnencrypted = false`, envoi de 20 Ko puis téléchargement de 200 Ko, 10 essais par case : runtime current-thread 0/10 réussis sans céder la main, 10/10 en cédant 4 fois, Kerberos comme NTLM ; runtime multi-thread 10/10 avec 0 ou 4 ; avec `AllowUnencrypted = true` aucun échec (7 téléchargements, 80 sorties de 1,5 Mo). Ces mesures précèdent le portail de connexion (`ConnGate`, voir « Tests ») qui supprime les cessions de main : à remesurer en session B, attendu 10/10 sans céder la main avec exactement 1 connexion par client | — non applicable (banc hors domaine) | n/a : pas de KDC sur cette VM | ✅ 2026-10-22 (atténué, avant le portail) ; ⏳ portail à mesurer en session B |
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
à `a19c202` (65/65, sans la feature `credssp`), puis à `ab82f50` (74/74 avec
`--features credssp,__internal`, en série comme en parallèle). `credssp_run_command_whoami`
n'est compilé qu'avec cette feature : il a été exécuté à part le 2026-10-21 à
`a19c202` (passé) et dans le run complet à 66 tests. Les noms sont ceux de
`tests/integration_real.rs`.

| Fonctionnalité | Tests | Server 2025 | Server 2012 R2 | Domaine (Kerberos) |
|---|---|---|---|---|
| Basic sur HTTP | `create_and_delete_shell`, `run_command_whoami`, `run_command_with_args`, `run_command_nonzero_exit` | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| Basic sur HTTPS | `basic_over_https_works` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| NTLM sur HTTP | `ntlm_run_command_whoami`, `ntlm_run_powershell`, `ntlm_shell_reuse` | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| NTLM sur HTTPS avec channel binding (CBT) | `ntlm_over_https_with_cbt` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| Les trois `EncryptionMode` (ces tests passaient aussi avant D3 grâce au repli en clair : ils ne prouvent pas le scellement, voir la ligne « Messages NTLM réellement scellés ») | `ntlm_encryption_always`, `ntlm_encryption_never`, `ntlm_encryption_auto_over_http` | ✅ 2026-10-21 | ✅ 2026-10-22 (suite complète) | — non applicable |
| CredSSP (`--features credssp`) | `credssp_run_command_whoami` | ✅ 2026-10-21 | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| CredSSP : en-têtes de réponse stricts, `Accept-Encoding: identity`, User-Agent winrm-rs | `credssp_reads_a_large_framed_response` (sortie de 300 000 octets), puis tous les tests `credssp_` | ⏳ à exécuter (banc) | ⏭ sauté sur 2012 R2 : aucune suite TLS commune avec rustls (voir « Limites connues ») | — non applicable |
| PowerShell, JSON, Unicode | `run_powershell_version`, `run_powershell_json_output`, `run_powershell_unicode`, `gather_host_facts_json` | ✅ 2026-10-21 | ✅ 2026-10-22 (`run_powershell_version`, `run_powershell_json_output`, `gather_host_facts_json`) ; `run_powershell_unicode` sauté : PowerShell 4.0 ignore `[Console]::OutputEncoding` sous `-EncodedCommand` (voir « Limites connues ») | — non applicable |
| Réutilisation d'un shell, démarrage et lecture manuels | `shell_reuse_multiple_commands`, `shell_start_command_and_receive` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| stdin | `shell_send_input_stdin` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Ctrl+C | `shell_signal_ctrl_c` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Annulation | `cancel_long_running_command`, `shell_run_powershell_with_cancel` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Idle timeout | `shell_with_idle_timeout_works` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Répertoire de travail | `shell_with_working_directory` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Variables d'environnement | `shell_with_env_vars` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Transferts de fichiers | `upload_and_download_file`, `upload_and_download_large_file`, `upload_and_download_binary_file` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| WQL | `wql_query_win32_operatingsystem`, `wql_query_win32_service`, `wql_query_custom_namespace`, `wql_query_invalid_namespace` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| `max_envelope_size` réduit | `small_max_envelope_size` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Retries | `retry_config_works_with_real_server` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Shells concurrents | `concurrent_shells` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| stderr CLIXML décodé (petit, gros, en flux) | `powershell_stderr_clixml_parsed`, `powershell_large_clixml_stderr_reassembled`, `streaming_large_clixml_stderr_reassembled` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Erreurs sur identifiants de shell invalides | `invalid_shell_id_returns_error`, `double_delete_shell_returns_error`, `command_on_deleted_shell_returns_error` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| `Shell::disconnect` refusé proprement sur un shell cmd | `shell_disconnect_returns_error_on_cmd_shell` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Proxy injoignable : erreur | `invalid_proxy_returns_http_error` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |
| Builder, user agent personnalisé | `builder_pattern_works`, `custom_user_agent_does_not_break` | ✅ 2026-10-21 | ✅ 2026-10-22 | — non applicable |

Les tests de préparation du banc (`setup_https_listener`, `enable_credssp_server`,
`enable_cbt_hardening_strict` et assimilés) ne sont pas des fonctionnalités ; ils
ne figurent pas dans la matrice.

## Limites connues

- **Kerberos : chiffrement des messages par `gss_wrap`, mesuré sur un seul
  contrôleur.** Depuis `c53acbe`, `EncryptionMode::Auto` scelle Kerberos sur
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
  connexion dédiée (`b1f5d7f`) : toute connexion suivante doit le
  présenter ; un certificat sans hachage de binding (Ed25519, algorithme
  inconnu) est refusé. L'épinglage vise le nom de serveur que `reqwest`
  transmet réellement (l'hôte de l'URL analysée : IDN en punycode, `10.1`
  en `10.0.0.1`, `win01?x` en `win01`) ; une fois épinglé, tout autre nom est
  refusé sauf la poignée de main propre au proxy `https://` (celui de
  `WinrmConfig::proxy`, sinon ceux de `HTTPS_PROXY` / `ALL_PROXY` ; un proxy
  tiré des réglages système, que `reqwest` ne lit qu'avec sa feature
  `system-proxy`, est refusé), et un hôte sans nom de serveur TLS valide est
  refusé avant l'AP-REQ (`0e61241`).
  `EncryptionMode::Never` sur HTTP simple n'a rien de tout cela. Côté serveur,
  l'intégrité sur HTTP face à un attaquant actif suppose `AllowUnencrypted =
  false` (NTLM comme Kerberos). La branche SSPI de `cross-krb5` (client
  Windows) n'est ni compilée ici ni testée : un job CI `kerberos-windows`
  (check + clippy) la compile en CI, sans test et sans résultat consulté ici ; sur un client Windows `Auto` scelle
  désormais, `EncryptionMode::Never` est le recours. L'hôte doit être le nom
  du serveur (SPN `HTTP/<hôte>`), pas une adresse ; le banc passe par une
  ligne `127.0.0.1 dc.winrm.test` dans `/etc/hosts`. Le port HTTPS `57986`
  du banc a été relayé le 2026-10-22 par un relais PowerShell non élevé sur
  la boucle locale (gsudo bloqué sur l'invite UAC), pas par le `netsh
  portproxy` décrit dans le README du banc.
- **Course du pool des connexions dédiées : fermée pour les connexions
  authentifiées.** `hyper` rend la connexion au pool du client depuis une
  tâche à lui ; une requête envoyée avant que cette tâche tourne fait courir
  la sortie du pool contre une connexion TCP neuve, et si la connexion neuve
  gagne, la requête part sans session et échoue en HTTP 401 (erreur, pas de
  renvoi) ; une connexion neuve perdante, terminée en arrière-plan, prenait
  en plus l'unique place libre du pool à la connexion authentifiée. Chaque
  client dédié (`AuthConn`) a désormais un portail (`ConnGate`) devant son
  connecteur : ouvert pendant la poignée de main (la sonde puis l'AP-REQ de
  Kerberos sur HTTPS ouvrent légitimement deux connexions), il est verrouillé
  dès que la connexion est authentifiée ; verrouillé, il refuse toute
  nouvelle connexion sans lancer le connecteur (ni TCP, ni proxy, ni TLS),
  après une attente de `min(1 s, connect_timeout_secs)` qui laisse la sortie
  du pool gagner. Les 4 cessions de main empiriques sont supprimées. Le
  correctif passe par `tower-layer` et `tower-service` (déjà dans
  `Cargo.lock` et exemptés dans `supply-chain/config.toml`), pas par
  hyper-util en dépendance directe. NTLM sur HTTPS (une poignée de main par
  requête) ne verrouille pas son portail. À remesurer en session B (ligne de
  la matrice) ; sur HTTPS (Kerberos `Auto`, connexion authentifiée une fois),
  la mesure d'avant le portail n'avait montré aucun échec (40/40), attendu
  depuis : exactement 2 connexions par essai.
- **Server 2012 R2 : suite complète mesurée, 12 tests sautés.** Run complet à
  `64c4a0b` (VM reconstruite, `vm-connect-2012r2.sh`, ports `56985`/`56986`) :
  81 passés dont 12 sautés, 0 échoué, en série comme en parallèle. Le format de
  trame scellée strict et tous les chemins HTTP (Basic, NTLM sur les trois
  `EncryptionMode`, proxy HTTP et SOCKS5, transferts, WQL, annulation, timeouts)
  y passent. Les sauts, avec leur cause :
  - neuf tests HTTPS (`basic_over_https_works`, `ntlm_over_https_with_cbt`,
    `ntlm_encryption_always_over_https`, `credssp_run_command_whoami`,
    `silent_command_completes_over_credssp`, `http_proxy_connect_carries_https`,
    `certificate_auth_whoami`, `certificate_auth_unmapped_cert_is_rejected`,
    `silent_command_completes_over_certificate_auth`) plus
    `setup_certificate_auth` : le SCHANNEL de 2012 R2 n'associe GCM qu'à
    l'échange de clés RSA statique alors que `rustls` ne gère ni le RSA statique
    ni CBC, de sorte qu'aucune suite n'est commune et que la poignée de main se
    termine en `tls handshake eof` ; en outre `setup_certificate_auth` y
    échoue à l'étape 4 car `netsh http update sslcert … clientcertnegotiation`
    n'existe pas sur cette version (les étapes 1 à 3, import de la CA et
    mappage, réussissent) ;
  - `run_powershell_unicode` : PowerShell 4.0 ignore
    `[Console]::OutputEncoding` sous `-EncodedCommand` ;
  - `max_output_bytes_counts_raw_clixml_stderr` : PowerShell 4.0 rend chaque
    `Write-Error` avec l'instruction source et un remplissage à 80 colonnes
    (91 360 octets décodés pour 40 erreurs, contre environ 29 Ko sur 2025), de
    sorte que la précondition du test (stderr décodé nettement sous le plafond
    de 64 Kio) ne peut pas tenir. Le plafonnement sur les octets bruts n'est donc
    pas mesuré sur 2012 R2 ; `max_output_bytes_aborts_and_releases_shell` y passe.
  `write_host_reaches_stdout_once`, ajouté après ce run, y saute seulement sa
  moitié brute (garde `is_server_2012_r2()`) : PowerShell 4.0 n'a pas de flux
  information et n'écrit donc pas de copie de `Write-Host` dans le stderr.
  Les lignes `psrp-rs` et `bridge-mcp` ne sont pas mesurées sur 2012 R2.
- **Les tests à timeout court dépendent de la charge du serveur.** Ceux qui
  utilisent un `operation_timeout_secs` de 15 s (`shell_run_command_times_out`,
  `signal_terminate_stops_running_command`,
  `silent_command_longer_than_operation_timeout_completes` et les trois
  `silent_command_completes_over_*`) font aussi passer la
  création du shell dans cette fenêtre : sous un run entièrement parallèle sur un
  serveur chargé, elle peut la dépasser et échouer par `TimedOut` (reproduit
  avec 24 sessions PowerShell liées au CPU lancées en parallèle sur l'hôte :
  `Err(Soap(TimedOut))` de `open_shell` après environ 15 s). Depuis,
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
- **Racines de confiance.** Par défaut, seules les racines webpki (Mozilla) sont reconnues. Depuis 1.5.0, `WinrmClientBuilder::add_root_certificates_pem` et `platform_roots` couvrent les CA internes ; le certificat de l'écouteur doit porter le nom d'hôte dans son SAN.
- **`WinrmClient::run_command`, `run_powershell` et `download_file` n'ont
  pas de délai total.** `operation_timeout_secs` borne chaque Receive, pas la
  commande. Depuis le correctif de D1, une commande bloquée et muette
  (`Read-Host`, `pause`, un processus bloqué) fait attendre l'appel jusqu'à sa
  fin au lieu d'échouer après environ `operation_timeout_secs` ; c'est un
  changement de comportement, documenté dans le `CHANGELOG` (`### Changed` et
  « Upgrading from 1.2.x ») et la rustdoc. Remède : les variantes à délai
  total `run_command_with_timeout`, `run_powershell_with_timeout` et
  `download_file_with_timeout` (`WinrmError::Timeout`), ou les variantes
  `*_with_cancel` (`WinrmError::Cancelled`) ; à l'expiration comme à
  l'annulation, elles demandent la terminaison de la commande puis
  suppriment le shell distant (au mieux, chaque étape bornée), ce que
  mesurent `run_powershell_with_timeout_expires_and_releases_shell` et
  `run_powershell_with_cancel_releases_shell`. Un `tokio::time::timeout`
  posé par l'appelant, lui, abandonne l'appel sans rien envoyer : le shell
  reste jusqu'à l'idle timeout du serveur. `Shell::run_command` garde son
  délai total de `2 * operation_timeout_secs`. `run_wql` ne scrute pas
  Receive et n'est pas concerné.
- **`Shell::run_command` n'arrête pas la commande quand il abandonne.** À son
  délai total (`WinrmError::Timeout(2 * operation_timeout_secs)`) ou au
  plafond `max_output_bytes` (`WinrmError::Transfer`), il rend l'erreur sans
  envoyer de terminaison : la commande continue dans le shell, qui reste
  ouvert jusqu'à `Shell::close` (ou l'idle timeout). Les méthodes de
  `WinrmClient` (`run_command`, `*_with_timeout`, `*_with_cancel`), elles,
  envoient la terminaison. Comportement antérieur à la campagne, inchangé.
- **Scellement NTLM et NTLM sur TLS : ce qui reste.** Les suites relevées
  par les audits sont traitées par `74578d2`, `9493f59` et `ad908b3` (repli
  en clair, Type 3 à corps vide, aucun renvoi d'une requête scellée, corps
  annoncé scellé non déchiffrable, session laissée en cache, contrôles de
  `unseal_body`, taille des réponses, cible de fuzz `fuzz_ntlm_unseal_body`,
  verrou global, jeton de liaison de canal (CBT) calculé sur le certificat
  de la connexion qui porte le défi, nouvelles tentatives limitées aux
  erreurs de connexion pour toutes les méthodes, au plus 32 échanges NTLM
  simultanés par client). Restent : `EncryptionMode::Never` envoie tout en
  clair sur HTTP (réservé au débogage) ; face à un serveur qui refuse le
  trafic non chiffré (`AllowUnencrypted = false`, réglage par défaut de
  Windows), le scellement n'est mesuré que sur le contrôleur de domaine,
  NTLM et Kerberos (`sealed_download_after_upload_stays_on_its_connection_allow_unencrypted_false`,
  `kerberos_sealed_with_allow_unencrypted_false`), le banc Server 2025
  l'autorise ; les cibles de fuzz (`fuzz_ntlm_unseal_body` comprise) sont
  compilées et rejouent leurs corpus (`scripts/fuzz.sh build` puis `smoke`,
  21 cibles), quatre d'entre elles (`fuzz_clixml_stderr`,
  `fuzz_ntlm_unseal_body`, `fuzz_kerberos_sealed`, `fuzz_asn1_cert`) ont
  tourné 20 s chacune sans plantage, mais aucune campagne longue n'a eu
  lieu, et `fuzz/Cargo.lock` a été rafraîchi (`cargo audit` propre) ; un proxy HTTP qui transfère les requêtes (sans tunnel) sans
  garder une connexion serveur par connexion cliente casse la liaison NTLM à
  la connexion : les requêtes scellées échouent alors, sans partir en clair ;
  une connexion inactive que le serveur a fermée sans l'annoncer est
  réauthentifiée une fois au lieu de donner un 401 : le portail verrouillé
  refuse la connexion neuve, la requête n'est donc pas partie, et elle est
  scellée avec la nouvelle session puis envoyée une seule fois ; un 401
  reçu après envoi fait toujours échouer la requête (`WinrmError::Ntlm`,
  « NOT resent ») au lieu de la renvoyer : `reqwest` n'expose pas l'adresse
  locale de la connexion qui a porté une réponse, donc une connexion perdue
  après l'envoi ne se détecte qu'à ce 401 (une réponse
  `Connection: close` fait déjà abandonner la connexion, et
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
  configuration TLS, ce certificat n'est pas compté (`f43bfb0`) ; testé en
  unitaire avec un proxy TLS en processus
  (`ntlm_cbt_through_an_https_proxy_binds_the_target_certificate`), pas en
  live (pas de proxy `https://` sur le banc). Proxy HTTP qui transfère sans
  tunnel : voir le point précédent (liaison NTLM à la connexion).
- **`bridge-mcp` (hors de ce dépôt, observation seulement).** Il n'interpole pas
  `${VAR}` alors que son `config.example.yaml` montre `${WIN_PASSWORD}` (la
  chaîne est envoyée telle quelle) et il convertit toute `AuthFailed` en
  « SSH authentication failed for unknown@WinRM », en perdant le message.
