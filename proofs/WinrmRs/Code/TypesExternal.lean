-- [winrm_rs]: external types.
--
-- Written by hand from `TypesExternal_Template.lean`, which Aeneas generates:
-- one declaration here for each one there. These are the types of the Rust
-- standard library that the translated code mentions and that the Lean
-- library of Aeneas does not model.
module
public import Aeneas
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

/-- [core::mem::maybe_uninit::MaybeUninit]
    Name pattern: [core::mem::maybe_uninit::MaybeUninit]

    Aeneas lists it among the external types it met, and no translated
    definition mentions it: it stays a type about which nothing is known. -/
@[rust_type "core::mem::maybe_uninit::MaybeUninit"]
axiom core.mem.maybe_uninit.MaybeUninit (T : Type _) : Type

