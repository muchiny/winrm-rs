import WinrmRs.Code.FunsExternal
open Aeneas Aeneas.Std Result

/-!
# What the hand-written models return

One theorem for each model of `WinrmRs/Code/FunsExternal.lean`. They are
`@[step]` theorems: the `step` tactic of Aeneas uses them to go through a
call to the function in the proof of a function that calls it.
-/

namespace WinrmRs

@[simp, scalar_tac_simps]
theorem Model.byte_val (n i : Nat) : (Model.byte n i).val = n / 256 ^ i % 256 := by
  simp [Model.byte]

/-- **Spec theorem for `core::num::{usize}::to_be_bytes`**
The eight bytes of `x`, the most significant one first. -/
@[step]
theorem to_be_bytes.step_spec (x : Std.Usize) :
    lift (core.num.Usize.to_be_bytes x) ⦃ (a : Array Std.U8 8#usize) =>
      a.val = [ Model.byte x.val 7, Model.byte x.val 6, Model.byte x.val 5,
                Model.byte x.val 4, Model.byte x.val 3, Model.byte x.val 2,
                Model.byte x.val 1, Model.byte x.val 0 ] ⦄ := by
  simp only [WP.spec_ok, lift, core.num.Usize.to_be_bytes, Array.make_val]

/-- **Spec theorem for `core::slice::{[T]}::split_first`** -/
@[step]
theorem split_first.spec {T : Type _} (s : Slice T) :
    core.slice.Slice.split_first s ⦃ (o : Option (T × Slice T)) =>
      match o with
      | none => s.val = []
      | some (x, tl) => s.val = x :: tl.val ⦄ := by
  unfold core.slice.Slice.split_first
  split <;> simp [*]

/-- **Spec theorem for `core::slice::{[T]}::split_at_checked`** -/
@[step]
theorem split_at_checked.spec {T : Type _} (s : Slice T) (mid : Std.Usize) :
    core.slice.Slice.split_at_checked s mid ⦃ (o : Option (Slice T × Slice T)) =>
      match o with
      | none => s.val.length < mid.val
      | some (a, b) =>
        mid.val ≤ s.val.length ∧ a.val = s.val.take mid.val ∧ b.val = s.val.drop mid.val ⦄ := by
  unfold core.slice.Slice.split_at_checked
  split <;> simp [*]
  omega

/-- **Spec theorem for `String::from(&str)`**
It returns; nothing is said of the text. -/
@[step]
theorem string_from.spec (s : Str) :
    alloc.string.String.Insts.CoreConvertFromShared0Str.from s ⦃ (_ : String) => True ⦄ := by
  simp [alloc.string.String.Insts.CoreConvertFromShared0Str.from]

end WinrmRs
