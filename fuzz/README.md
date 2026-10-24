# Fuzzing `winrm-rs`

21 libFuzzer targets covering everything the crate parses off the network and
everything it splices into an outgoing request. Driven through
[`scripts/fuzz.sh`](../scripts/fuzz.sh).

```bash
scripts/fuzz.sh list                          # targets and dictionaries
scripts/fuzz.sh build                         # compile all targets
scripts/fuzz.sh smoke                         # replay committed seeds, no mutation
scripts/fuzz.sh run                           # 60s per target
scripts/fuzz.sh run fuzz_asn1_ts_request 900  # one target, 15 minutes
scripts/fuzz.sh cmin                          # shrink the corpora
scripts/fuzz.sh coverage fuzz_soap_parse      # per-target coverage profile
```

Requires the nightly toolchain and `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

Targets are grouped by the surface they attack. "Source" is the code the target
drives; "invariant" is what it asserts beyond *must not panic*.

### NTLM wire format — server-controlled bytes

| Target | Source | Invariant |
|---|---|---|
| `fuzz_ntlm_parse` | `ntlm/messages.rs::parse_challenge` | parsed `TargetInfo` never exceeds its source message |
| `fuzz_ntlm_challenge_header` | same, magic-prefixed inputs | — |
| `fuzz_ntlm_header_decode` | `decode_challenge_header` | base64 framing does not change message validity |
| `fuzz_ntlm_av_pairs` | `crypto::parse_av_pairs`, `from_utf16le` | decoded text never exceeds its code-unit count |
| `fuzz_ntlm_type3` | `create_authenticate_message*` | every Type 3 security buffer stays inside the message, and the declared lengths fill it exactly |

### NTLM crypto and session state

| Target | Source | Invariant |
|---|---|---|
| `fuzz_ntlm_crypto` | NTOWFv1/v2, client blob, CBT, RC4, UTF-16 | blob framing is exact; RC4 self-inverse; UTF-16 roundtrips |
| `fuzz_ntlm_seal` | `NtlmSession::seal`/`unseal` | seal prepends exactly 16 bytes |
| `fuzz_ntlm_session` | multi-message seal/sign/unseal | signature version and sequence numbering across a conversation |
| `fuzz_ntlm_unseal_body` | `auth/ntlm.rs::unseal_body` (MS-WSMV multipart/encrypted framing) | never panics; errors do not echo the body; a server-sealed frame round-trips exactly; a flipped bit is rejected or leaves the plaintext unchanged; any truncation is rejected |
| `fuzz_kerberos_sealed` | `auth/sealed.rs::parse` with the Kerberos header rule, `auth/kerberos.rs` `check_acceptor_sealed` / `windows_layout`, `soap/parser.rs::check_relates_to` (no KDC needed) | never panics; errors stay short; a parsed token is a 16..=1024-byte header plus exactly `Length` bytes; the layout conversion keeps the data, writes RRC = trailer length and is a right rotation by it |

### SOAP

| Target | Source | Invariant |
|---|---|---|
| `fuzz_soap_parse` | `soap/parser.rs` response parsers | decoded streams fit in the response; a fault is never read as success |
| `fuzz_soap_enumerate` | `parse_enumerate_response` | an `EndOfSequence` element after the document clears the context; escaped item text never does and is never a fault; the context cannot add XML elements to the next `Pull` |
| `fuzz_soap_envelope` | all envelope builders | **no input can add XML markup** — tag counts match an empty-input baseline |
| `fuzz_xml_escape` | `envelope::xml_escape` | complete (no raw markup survives) and reversible |
| `fuzz_clixml_stderr` | `soap/clixml.rs::ClixmlDecoder` | output does not depend on how stderr is sliced; plain stderr passes through; output ≤ 3× input |

### Input validation

| Target | Source | Invariant |
|---|---|---|
| `fuzz_transport_host` | `transport::sanitize_host`, `transport::validate_host` | no `/` or `@` survives; the rebuilt URL has one authority; an accepted host has no `?`, `#`, `\`, whitespace or control character, and its endpoint URL (when the URL parser takes it) reads back with that host, the port, `/wsman`, and no userinfo, query or fragment |
| `fuzz_transfer_path` | `validate_remote_path`, `escape_ps_single_quoted` | accepted paths are bounded and control-free; every PowerShell single quote (U+0027, U+2018, U+2019, U+201A, U+201B) is doubled with itself and collapses back to the input |
| `fuzz_powershell_encode` | `command::encode_powershell_command` | output is ASCII base64 and roundtrips |

### CredSSP ASN.1 / DER — pre-authentication attack surface

| Target | Source | Invariant |
|---|---|---|
| `fuzz_asn1_ts_request` | `decode_ts_request`, `encode_ts_request`, `encode_ts_credentials` | encode → decode is the identity for every field |
| `fuzz_asn1_spnego` | `decode_spnego_token`, `decode_spnego_mech_list_mic`, `encode_spnego_init/response` | both wrappers roundtrip; the `mechListMIC` does not disturb the token and comes back out unchanged; a `NegTokenInit` is refused by the MIC extractor |
| `fuzz_asn1_cert` | `extract_subject_public_key` | extracted key fits inside the certificate |

## Layout

```
fuzz/
  fuzz_targets/     one file per target
  dict/             libFuzzer dictionaries: ntlm, soap, asn1, shell
  seeds/            committed starting corpus (regenerate: scripts/gen-fuzz-seeds.py)
  corpus/           evolving corpus, git-ignored, cached in CI
  artifacts/        crash reproducers, git-ignored
```

Each target is run against **both** `corpus/<target>` (writable) and
`seeds/<target>` (read-only), with the dictionary named in `scripts/fuzz.sh`.

## How the targets reach crate internals

Everything under test is private. The `__internal` feature exposes
`winrm_rs::__fuzz`, a `#[doc(hidden)]` module of thin wrappers over crate
internals ([`src/__fuzz.rs`](../src/__fuzz.rs)). Wrappers rather than
re-exports, so enabling the feature cannot widen the real API surface. It is
exempt from SemVer — downstream code must not enable it.

Fuzz builds keep `debug-assertions` and `overflow-checks` on (see
`fuzz/Cargo.toml`), so an arithmetic wrap in a parser aborts instead of
silently producing a wrong offset.

## Reproducibility

`create_authenticate_message_full` draws its client challenge from the CSPRNG,
which makes Type 3 output non-deterministic. In debug-assertion builds it
honours `CREDSSP_FIXED_CC`; `scripts/fuzz.sh` sets it, so `fuzz_ntlm_type3`
replays identically. The challenge timestamp is supplied by the target rather
than read from the clock for the same reason.

To replay a crash:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

## CI

- **`ci.yml` → `fuzz`** (every PR): builds all targets, replays the seed
  corpora, then fuzzes each target for 20s. Part of the `ci-pass` gate.
- **`fuzz.yml` → `campaign`** (nightly at 03:17 UTC, or on demand): 15 minutes
  per target under ASan, plus a sanitizer-free pass on the four parsers where
  overflow checks are the more useful detector. The corpus is cached per target
  and minimised after each run; crashes upload as artifacts.

## Adding a target

1. Write `fuzz_targets/fuzz_<name>.rs`. Assert an invariant, not just absence
   of panics — a target that only checks "did not crash" finds far less.
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add `"fuzz_<name>:<dict>"` to `TARGETS` in `scripts/fuzz.sh`.
4. Add seeds to `SEED_SETS` in `scripts/gen-fuzz-seeds.py`, rerun it, commit.
5. Add the target to the matrix in `.github/workflows/fuzz.yml`.
6. If it needs a crate internal, add a wrapper to `src/__fuzz.rs`.
