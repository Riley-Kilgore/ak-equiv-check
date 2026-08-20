import Lake
open Lake DSL

package «EquivBlasterBackend» where
  moreGlobalServerArgs := #["--threads=4"]
  moreLeanArgs := #["--threads=4"]

require Blaster from git
  "https://github.com/input-output-hk/Lean-blaster" @ "402f6d22c1fc42e6e26255faac77e15b2450e4ab"
require PlutusCore from git
  "https://github.com/input-output-hk/PlutusCoreBlaster" @ "4ef48606303c45225d3ed2e2a87fc50280a763b7"
require CardanoLedgerApi from git
  "https://github.com/input-output-hk/CardanoLedgerApiBlaster" @ "577e3eb03b5be09354cfdb1c0d0c12e9e16541a0"
