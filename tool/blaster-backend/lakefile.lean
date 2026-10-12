import Lake
open Lake DSL

package «EquivBlasterBackend» where
  moreGlobalServerArgs := #["--threads=4"]
  moreLeanArgs := #["--threads=4"]

require Blaster from git
  "https://github.com/input-output-hk/Lean-blaster" @ "ab82a3cb647cbdecc198202244622554e2464e4d"
require PlutusCore from git
  "https://github.com/input-output-hk/PlutusCoreBlaster" @ "4ef48606303c45225d3ed2e2a87fc50280a763b7"
require CardanoLedgerApi from git
  "https://github.com/input-output-hk/CardanoLedgerApiBlaster" @ "577e3eb03b5be09354cfdb1c0d0c12e9e16541a0"
