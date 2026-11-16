/-!
# DER length fields: what the Rust code has to do

Plain definitions on numbers and lists, with no Rust in them. The theorems of
`WinrmRs/Properties/Asn1Length.lean` say that `encode_length` and
`decode_length` of `src/asn1.rs` compute what these do. A proof is worth what
its statement is worth, so this file is the one to read and to agree with: it
is kept short, and the examples at the end pin a few values.
-/

namespace WinrmRs.Spec

/-- The DER encoding of a length below 2^32, as byte values. Below 128 it is
    the length itself, on one byte. Above, a first byte gives, with its high
    bit set, how many bytes follow, and they spell the length, the most
    significant byte first, on as few bytes as it takes. -/
def derLength (n : Nat) : List Nat :=
  if n < 0x80 then [n]
  else if n < 0x100 then [0x81, n]
  else if n < 0x10000 then [0x82, n / 0x100, n % 0x100]
  else if n < 0x1000000 then [0x83, n / 0x10000, n / 0x100 % 0x100, n % 0x100]
  else [0x84, n / 0x1000000, n / 0x10000 % 0x100, n / 0x100 % 0x100, n % 0x100]

/-- The number that bytes spell, the most significant one first, after `acc`. -/
def beValueFrom (acc : Nat) (bytes : List Nat) : Nat :=
  bytes.foldl (fun a b => a * 256 + b) acc

/-- What reading a length field gives, on byte values: the length and the
    bytes after the field, or nothing when the field is refused.

    A field is one byte below 128, or a first byte announcing one to three
    more. So a length that is read is below 2^24, whatever the input: the
    form on five bytes, which `derLength` writes from 2^24 up, is refused.
    The encoding is not required to be the shortest one: `0x81 0x05` is read
    as 5, which DER forbids and BER allows. -/
def decodeLength : List Nat → Option (Nat × List Nat)
  | [] => none
  | first :: rest =>
    if first < 0x80 then some (first, rest)
    else
      let k := first % 0x80
      if 1 ≤ k ∧ k ≤ 3 ∧ k ≤ rest.length then
        some (beValueFrom 0 (rest.take k), rest.drop k)
      else none

example : derLength 5 = [0x05] := by decide
example : derLength 300 = [0x82, 0x01, 0x2C] := by decide
example : derLength 0x1000000 = [0x84, 0x01, 0x00, 0x00, 0x00] := by decide

example : decodeLength [0x82, 0x01, 0x2C, 0xAA] = some (300, [0xAA]) := by decide
-- Not the shortest encoding of 5, and read all the same.
example : decodeLength [0x81, 0x05] = some (5, []) := by decide
-- The form on five bytes.
example : decodeLength [0x84, 0x01, 0x00, 0x00, 0x00] = none := by decide
-- The indefinite form of BER.
example : decodeLength [0x80] = none := by decide
-- Two bytes announced, one present.
example : decodeLength [0x82, 0x01] = none := by decide

end WinrmRs.Spec
