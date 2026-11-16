import WinrmRs.Properties.Asn1Length

/-!
# What the theorems rest on

`#print axioms` lists every axiom a theorem depends on, through all the
definitions and lemmas it uses. The three below are the axioms of Lean's own
logic, which every Mathlib theorem uses. A proof left unfinished would add
`sorryAx` to the list, and an `axiom` declared in this project would be named
in it: `#guard_msgs` then fails the build, since the message would no longer
be the one written here.
-/

namespace WinrmRs

/-- info: 'WinrmRs.asn1.encode_length.total' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms asn1.encode_length.total

/-- info: 'WinrmRs.asn1.encode_length.spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms asn1.encode_length.spec

/-- info: 'WinrmRs.asn1.decode_length.spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms asn1.decode_length.spec

/-- info: 'WinrmRs.asn1.decode_length.bounded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms asn1.decode_length.bounded

/-- info: 'WinrmRs.asn1.decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms asn1.decode_encode

/-- info: 'WinrmRs.asn1.decode_encode_refused' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms asn1.decode_encode_refused

end WinrmRs
