-- [winrm_rs]: external functions.
--
-- Written by hand from `FunsExternal_Template.lean`, which Aeneas generates:
-- one definition here for each axiom there, with the same name and type.
-- These are the functions of the Rust standard library that the proved code
-- calls and that the Lean library of Aeneas does not model. The proofs hold
-- for the definitions below, so each one states, in a comment, the Rust
-- behaviour it stands for. They are part of what the proofs assume.
module
public import Aeneas
public import WinrmRs.Code.Types
@[expose] public section
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option linter.style.whitespace false
set_option linter.style.setOption false
set_option linter.style.longLine false
set_option linter.internalConstructors false

set_option maxHeartbeats 1000000
set_option maxRecDepth 2048
open WinrmRs

/-- Byte `i` of `n`, counted from the least significant one. -/
def WinrmRs.Model.byte (n i : Nat) : Std.U8 :=
  UScalar.ofNatCore (n / 256 ^ i % 256) (by
    simp only [UScalarTy.U8_numBits_eq, Nat.reducePow]
    exact Nat.mod_lt _ (by decide))

/-- [core::num::{usize}::to_be_bytes], on a target whose `usize` is 64 bits.

    Rust: the bytes of the integer, the most significant one first. Aeneas
    knows the function but its library has no definition of it for `usize`,
    whose width depends on the target; `Funs.lean` was extracted for
    `x86_64` and reads an array of 8 bytes, so that is the width modelled.
    It is not in the template for the same reason. -/
def core.num.Usize.to_be_bytes (x : Std.Usize) : Array Std.U8 8#usize :=
  Array.make 8#usize
    [ WinrmRs.Model.byte x.val 7, WinrmRs.Model.byte x.val 6,
      WinrmRs.Model.byte x.val 5, WinrmRs.Model.byte x.val 4,
      WinrmRs.Model.byte x.val 3, WinrmRs.Model.byte x.val 2,
      WinrmRs.Model.byte x.val 1, WinrmRs.Model.byte x.val 0 ]

/-- The fold of `f` over a list, threading the closure's state. -/
def WinrmRs.Model.foldList
  {T : Type _} {B : Type _} {F : Type _}
  (inst : core.ops.function.FnMut F (B × T) B) :
  List T → B → F → Result B
  | [], acc, _ => ok acc
  | x :: xs, acc, f =>
    Aeneas.Std.bind (inst.call_mut f (acc, x))
      (fun r => WinrmRs.Model.foldList inst xs r.1 r.2)

/-- [core::slice::iter::{impl core::iter::traits::iterator::Iterator<&'a T> for core::slice::iter::Iter<'a, T>}::fold]:
    Name pattern: [core::slice::iter::{core::iter::traits::iterator::Iterator<core::slice::iter::Iter<'a, @T>, &'a @T>}::fold]

    Rust: calls `f(acc, x)` on each remaining element `x`, first to last,
    starting from `init`, and returns the last `acc`. The remaining elements
    of an `Iter` are `slice[i..]` in the model of Aeneas. -/
@[rust_fun
  "core::slice::iter::{core::iter::traits::iterator::Iterator<core::slice::iter::Iter<'a, @T>, &'a @T>}::fold"]
def core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold
  {T : Type _} {B : Type _} {F : Type _} (opsfunctionFnMutFPairBSharedATBInst :
  core.ops.function.FnMut F (B × T) B)
  (it : core.slice.iter.Iter T) (init : B) (f : F) : Result B :=
  WinrmRs.Model.foldList opsfunctionFnMutFPairBSharedATBInst
    (it.slice.val.drop it.i) init f

/-- [core::slice::{[T]}::split_first]:
    Name pattern: [core::slice::{[@T]}::split_first]

    Rust: `None` for an empty slice, otherwise the first element and the
    rest. -/
@[rust_fun "core::slice::{[@T]}::split_first"]
def core.slice.Slice.split_first
  {T : Type _} (s : Slice T) : Result (Option (T × (Slice T))) :=
  match h : s.val with
  | [] => ok none
  | x :: tl =>
    ok (some (x, Slice.from tl (by
      have := s.property
      simp only [h, List.length_cons] at this
      scalar_tac)))

/-- [core::slice::{[T]}::split_at_checked]:
    Name pattern: [core::slice::{[@T]}::split_at_checked]

    Rust: `None` when `mid > len`, otherwise `[0, mid)` and `[mid, len)`. -/
@[rust_fun "core::slice::{[@T]}::split_at_checked"]
def core.slice.Slice.split_at_checked
  {T : Type _} (s : Slice T) (mid : Std.Usize) :
  Result (Option ((Slice T) × (Slice T))) :=
  if mid.val ≤ s.val.length then
    ok (some
      (Slice.from (s.val.take mid.val) (by
         have := s.property
         simp only [List.length_take]
         scalar_tac),
       Slice.from (s.val.drop mid.val) (by
         have := s.property
         simp only [List.length_drop]
         scalar_tac)))
  else ok none

/-- The text of a Rust `str` as a Lean `String`. Kept abstract: no proof
    reads the text of an error message. -/
opaque WinrmRs.Model.stringOfStr : Str → String

/-- [alloc::string::{impl core::convert::From<&'_0 str> for alloc::string::String}::from]:
    Name pattern: [alloc::string::{core::convert::From<alloc::string::String, &'0 str>}::from]

    Rust: copies the text into a new `String`; it returns for every input
    (an allocation failure aborts the process, which is outside the model). -/
@[rust_fun
  "alloc::string::{core::convert::From<alloc::string::String, &'0 str>}::from"]
def alloc.string.String.Insts.CoreConvertFromShared0Str.from
  (s : Str) : Result String :=
  ok (WinrmRs.Model.stringOfStr s)
