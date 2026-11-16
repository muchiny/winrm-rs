import Lake
open Lake DSL

-- The Lean library of Aeneas, at the commit of the release whose `aeneas` and
-- `charon` binaries `scripts/lean.sh` pins (nightly-2026.11.09-5a392f4). The
-- two must move together: the generated code targets this library.
require aeneas from git
  "https://github.com/AeneasVerif/aeneas.git" @
    "5a392f4b80a4d0d05abc240eb2a7fa70622a9a35" / "backends/lean"

package «winrm-rs-proofs»

@[default_target]
lean_lib WinrmRs
