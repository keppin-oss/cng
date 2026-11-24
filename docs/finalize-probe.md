# Finalize probe: procedure

`TestFinalizeFailureProbe` (`windowscng/finalize_probe_windows_test.go`, build
tag `cng_finalize_probe`) is the native check behind one rule of the package:
for a **non-privileged** caller, `NCryptFinalizeKey` denied with `NTE_PERM`
followed by `NTE_BAD_KEYSET` from deleting the never finalized key means that
the key was not persisted, so the error does not wrap `ErrCleanupFailed`.

The probe creates and deletes temporary machine keys, and some cells need a
second account or a scheduled task. Run it only on a dedicated test machine,
with the approval of the owner of that machine.

## What one cell is

A cell is one caller context and one SDDL, tested in three processes with one
unique key name:

1. **observe**, elevated: the name is absent by enumeration and by exact open,
   with a temporary positive control key `<name>.Control` that both methods
   must find and then stop finding after it is deleted;
2. **run**, in the declared context: the production create path runs with the
   chosen SDDL, and the result is classified;
3. **observe** again, elevated: the name is still absent.

The run phase passes only with `EXPECTED`:

| Outcome | Meaning |
|---|---|
| `EXPECTED` | create, export policy, DACL and finalize ran in order; finalize `NTE_PERM`; delete `NTE_BAD_KEYSET` on the same handle; one free, with its status recorded; one non-privileged privilege check; the error is the finalize `NCryptError` with the "not persisted" note and without `ErrCleanupFailed` |
| `DIFFERENT` | finalize was reached but something above differs. A finalize that succeeds is reported here, and the probe deletes that key through its handle |
| `NOT_EXERCISED` | a step before finalize failed: the rule was not reached |
| `INVALID_CONFIGURATION` | the token does not match the declared context, the name already exists, or an input is invalid; nothing is created |

`DIFFERENT` and `NOT_EXERCISED` are observations to report as they are, not
configurations to change until `NTE_PERM` appears. Only the observe phases,
run elevated, show absence: for a non-privileged caller `NTE_BAD_KEYSET` does
not distinguish an absent key from an inaccessible one. Enumeration and exact
open show only what the KSP exposes; they do not prove that no partial file
exists on disk.

## Matrix

| Context (`-probe.context`) | Token | `legacy` | `privileged-only` | `service:<Name>` |
|---|---|---|---|---|
| `filtered-admin` | Administrator, non-elevated: Administrators is deny-only | control of repeatability | cell | cell |
| `standard-user` | local account without Administrators | cell | cell | cell |
| `local-service` | `NT AUTHORITY\LOCAL SERVICE` (S-1-5-19) | cell | cell | cell |

**Recorded run.** On Windows NT 10.0.26200 (25H2), with product code
identical to v0.3.0, all nine cells gave `EXPECTED`, with `ABSENT` before and
after:
- finalize was denied with `0x80090010`;
- the delete reported `0x80090016`;
- the free returned `0x0`.

The `local-service` cells ran from a scheduled task, so their tokens held no
service SID.

`-probe.sddl` selects the DACL written before finalize: `legacy` is the
`PolicyServiceSigner` DACL (the one the `LoadOrCreate` of v0.4.0 and earlier
requested), `privileged-only` the `PolicyPrivilegedOnly` DACL,
`service:<Name>` the DACL of `NewServicePolicy(<Name>)`. The service does not
need to exist. A service SID written in the SDDL is not the same as a token
that holds it: the token is recorded, including any service SID.

`Create` creates keys only for privileged callers, so the probe calls the
internal create path directly (`createPersistedKeyWith`). That is the exact
path `Create` uses.

## Preparation (elevated PowerShell)

```powershell
$root = "C:\KeppinProbe"
New-Item -ItemType Directory -Force "$root\logs" | Out-Null
go test -c -tags cng_finalize_probe -o "$root\finalize-probe.exe" ./windowscng
$commit = git rev-parse HEAD
```

For the `standard-user` and `local-service` cells, those callers must be able
to run the binary and write the log:

```powershell
icacls "$root" /grant "*S-1-5-19:(OI)(CI)RX" "<Computer>\<StandardUser>:(OI)(CI)RX"
icacls "$root\logs" /grant "*S-1-5-19:(OI)(CI)M" "<Computer>\<StandardUser>:(OI)(CI)M"
```

Choose a run ID and, per cell, a unique name, for example
`Keppin.OSS.Test.Finalize.<RunID>.<context>.<sddl>`. Names must start with
`Keppin.OSS.Test.`. Every flag also has an environment variable
(`KEPPIN_FINALIZE_PROBE_PHASE`, `…_NAME`, `…_CONTEXT`, `…_SDDL`, `…_LOG`,
`…_COMMIT`), but flags are what reaches a process started by `runas` or by a
scheduled task.

## One cell

Pass every flag as a **quoted string**, in the `-flag=value` form. Windows
PowerShell 5.1 splits an unquoted argument such as `-test.run` at the dot, and
the binary then fails with `flag provided but not defined: -test` without
writing any record. PowerShell 7 does not, but the quoted form works in both.

Common arguments (one log file per cell), in every PowerShell window of the
cell:

```powershell
$root = "C:\KeppinProbe"; $commit = "<commit>"
$name = "Keppin.OSS.Test.Finalize.R1.filtered-admin.legacy"
$common = @('-test.run=TestFinalizeFailureProbe', '-test.v', "-probe.name=$name", "-probe.log=$root\logs\$name.jsonl", "-probe.commit=$commit")
```

1. **observe**, elevated PowerShell:
   ```powershell
   & "$root\finalize-probe.exe" @common '-probe.phase=observe'
   ```
2. **run**, in the context of the cell:
   - `filtered-admin`, from a **non-elevated** PowerShell:
     ```powershell
     & "$root\finalize-probe.exe" @common '-probe.phase=run' '-probe.context=filtered-admin' '-probe.sddl=legacy'
     ```
   - `standard-user`: `runas` takes the whole command as one string, which is
     not affected by the splitting. The paths must not contain spaces, and a
     user name with a space is quoted:
     ```powershell
     runas '/user:<Computer>\<Standard User>' "$root\finalize-probe.exe $($common -join ' ') -probe.phase=run -probe.context=standard-user -probe.sddl=legacy"
     ```
   - `local-service`: write the command into `$root\run-ls.cmd`, because
     `schtasks /TR` is limited to 261 characters. `cmd.exe` does not split the
     flags:
     ```
     "C:\KeppinProbe\finalize-probe.exe" -test.run=TestFinalizeFailureProbe -test.v -probe.phase=run -probe.context=local-service -probe.sddl=legacy -probe.name=<name> -probe.log=C:\KeppinProbe\logs\<name>.jsonl -probe.commit=<commit> > C:\KeppinProbe\logs\<name>.run.txt 2>&1
     ```
     Then:
     ```powershell
     schtasks /Create /TN KeppinFinalizeProbe /RU "NT AUTHORITY\LOCALSERVICE" /SC ONCE /ST 23:59 /F /TR "$root\run-ls.cmd"
     schtasks /Run /TN KeppinFinalizeProbe
     # wait until the record appears in the log, then:
     schtasks /Delete /TN KeppinFinalizeProbe /F
     ```
3. **observe** again, elevated, with the same command as step 1.

The cell is complete when its log has three records (observe, run, observe),
both observe records report `ABSENT`, and the run record has an outcome.

## Evidence

Keep these records for each run:

- every `.jsonl` log, unedited;
- a manifest with the hash of each log and of the binary:
  ```powershell
  Get-FileHash "$root\logs\*.jsonl", "$root\finalize-probe.exe" -Algorithm SHA256 |
    Format-Table Hash, Path -AutoSize | Out-File "$root\manifest.txt"
  ```
- the commit of the code and the Windows build, which every record also holds.

Each record holds: time, phase, name, commit, Windows build, KSP, token (user
SID, elevation type, integrity level, privilege check, Administrators state,
service SIDs), context, SDDL, every native step with its status, the error,
the outcome and the reasons for it.

## Cleanup

- Delete the scheduled task if it still exists.
- Revoke the `icacls` grants and remove `C:\KeppinProbe` when the evidence is
  kept elsewhere.
- Never delete keys by prefix. A key the probe may have left is deleted only
  by its exact name, after an elevated observe shows it.
