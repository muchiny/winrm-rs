# Lean proofs

Mathematical proofs about a few functions of `winrm-rs`, checked by the
[Lean 4](https://lean-lang.org) proof assistant.

A test runs a function on some inputs. A proof is about **every** input: once
Lean accepts the theorem "`decode_length` returns for all bytes", there is no
input left that makes it panic. The price is that a proof is long to write, so
only small functions that matter are proved: for now the two that write and
read the length field of an ASN.1 value, in [`src/asn1.rs`](../src/asn1.rs).
The second one reads bytes sent by a server before it is authenticated.

Nothing here is compiled into the crate, and nothing here is published to
crates.io. The Rust code is not changed for the proofs.

## How it works

```
src/asn1.rs ──Charon──▶ .llbc ──Aeneas──▶ WinrmRs/Code/*.lean ──Lean──▶ proofs checked
 (the Rust)                                (the same functions,          against
                                            written in Lean)             WinrmRs/Spec
```

1. [Charon](https://github.com/AeneasVerif/charon) reads the two functions out
   of the Rust compiler.
2. [Aeneas](https://github.com/AeneasVerif/aeneas) writes them again as Lean
   definitions. This is done by a tool, not by hand, and the result is
   committed in `WinrmRs/Code/`.
3. The theorems of `WinrmRs/Properties/` are statements about these
   definitions, and Lean checks their proofs.

## What is proved

| Theorem | In plain words |
|---|---|
| `asn1.encode_length.total` | The encoder returns for every length, with one to five bytes. |
| `asn1.encode_length.spec` | Below 2^32, these bytes are the DER encoding of the length. |
| `asn1.decode_length.spec` | The decoder returns for every input: no panic, no overflow, no read out of bounds. It accepts exactly the fields `Spec.decodeLength` accepts, with the same length and the same remaining bytes. |
| `asn1.decode_length.bounded` | A length the decoder accepts is below 2^24, and it consumed one to four bytes of the input, no more. |
| `asn1.decode_encode` | Below 2^24, decoding what was encoded gives the length back, and the bytes after it untouched. |
| `asn1.decode_encode_refused` | From 2^24 up, the decoder refuses what the encoder wrote. |

Two things the proofs made precise, and that no test said:

- `encode_length` is only right **below 2^32**. On a 64-bit target, a larger
  length would be written with its four low bytes alone. No message of
  4 GiB is ever built, so this is a limit and not a bug, but it is now
  written down, as the hypothesis of `asn1.encode_length.spec`.
- `decode_length` reads an encoding that is not the shortest one (`0x81 0x05`
  for 5). DER forbids it, BER allows it.

## What is assumed

A proof removes doubt about the reasoning, not about its starting points.
These are the starting points:

- **The translation.** Charon and Aeneas are trusted to write Lean code that
  behaves as the Rust does.
- **The standard library.** The two functions call five functions of `std`
  that Aeneas has no model of. They are modelled by hand in
  [`WinrmRs/Code/FunsExternal.lean`](WinrmRs/Code/FunsExternal.lean), each
  with a comment that says what the Rust one does: `usize::to_be_bytes`,
  `split_first`, `split_at_checked`, `Iterator::fold` on a slice, and
  `String::from(&str)`.
- **The target.** `usize` is 64 bits (`x86_64`), which is what the code was
  translated for.
- **The specification.** [`WinrmRs/Spec/Asn1Length.lean`](WinrmRs/Spec/Asn1Length.lean)
  says what a DER length is. If it says the wrong thing, the proofs prove the
  wrong thing. It is short, with examples: read it first.
- **Lean itself**, and its three usual axioms. `WinrmRs/Audit.lean` fails the
  build if a theorem comes to depend on anything else, an unfinished proof
  (`sorry`) included.

And the proofs say nothing about the rest of the crate.

## Layout

```
proofs/
├── lean-toolchain            the version of Lean
├── lakefile.lean             the project, and the version of the Aeneas library
├── lake-manifest.json        the exact commits of every Lean dependency
├── WinrmRs.lean              the root: imports everything
└── WinrmRs/
    ├── Code/                 the Rust functions in Lean
    │   ├── Types.lean, Funs.lean      generated: do not edit
    │   ├── *_Template.lean            generated: what std functions need a model
    │   └── FunsExternal.lean, TypesExternal.lean   written by hand: the models
    ├── Spec/                 what the functions have to do, in plain Lean
    ├── Properties/           the theorems and their proofs
    └── Audit.lean            what the theorems depend on
```

To read a result without reading a proof: the statement of a theorem is what
stands between `theorem` and `:= by`. `f x ⦃ r => P r ⦄` means "`f x` returns,
and its result `r` satisfies `P`".

## Running it

Everything goes through [`scripts/lean.sh`](../scripts/lean.sh):

```bash
scripts/lean.sh tools     # once: fetch the pinned Aeneas and its Rust nightly
scripts/lean.sh extract   # Rust -> WinrmRs/Code/
scripts/lean.sh check     # Lean checks every proof
scripts/lean.sh drift     # extract, then fail if the committed code differs
scripts/lean.sh all       # drift, then check: what CI runs
```

It needs Linux on `x86_64`, `rustup`, the OpenSSL headers (`asn1.rs` is behind
the `credssp` feature) and [elan](https://github.com/leanprover/elan), which
is to Lean what `rustup` is to Rust. The first run downloads the compiled
files of Mathlib: count 11 GB of disk in all, and nothing to compile. After
that, `extract` and `check` take about twenty seconds each.

To read or write proofs, open the `proofs/` folder itself in VS Code with the
Lean 4 extension: it shows, at each line of a proof, what remains to prove.

The `Proofs` workflow runs `drift` and `check` on a pull request that touches
`src/`, the Cargo files or this folder.

## When the Rust changes

A change to `encode_length` or `decode_length` changes `WinrmRs/Code/Funs.lean`:

1. `scripts/lean.sh extract`, and look at the diff of `WinrmRs/Code/`;
2. `scripts/lean.sh check`: either the proofs still pass, or Lean points at the
   step that no longer holds, which is then a proof to repair or a bug to fix;
3. commit the generated files with the Rust change.

A change anywhere else in the crate leaves the generated files as they are.

## Proving another function

1. Add its path to `START_FROM` in `scripts/lean.sh`, and run `extract`.
2. If `FunsExternal_Template.lean` has a new `axiom`, the function calls
   something of `std` that has no model yet: write one in `FunsExternal.lean`,
   with the same name and type.
3. Say what the function has to do in `WinrmRs/Spec/`, state and prove the
   theorems in `WinrmRs/Properties/`, and add them to `WinrmRs/Audit.lean`.

Aeneas translates a subset of safe Rust, and stops with an error on what it
does not support. Proving is practical on code without I/O: parsers, encoders,
arithmetic. The [Aeneas repository](https://github.com/AeneasVerif/aeneas)
documents the tactics the proofs use (`step`, `scalar_tac`).

## Versions

Aeneas has no stable release, only a build a day, so three pins move together:

- `AENEAS_TAG` and `AENEAS_SHA256` in `scripts/lean.sh` (the `aeneas` and
  `charon` binaries, and the Rust nightly Charon is built against);
- the commit of `require aeneas` in `lakefile.lean` (the Lean library the
  generated code is written for), followed by `lake update` in this folder;
- `lean-toolchain`, to the version that commit of Aeneas uses.
