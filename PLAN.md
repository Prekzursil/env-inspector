# Env Inspector Reliability Upgrade Plan (Windows + WSL + Multi-Source Editing)

## Summary

Build a robust `CLI core` and keep `Tkinter` as the GUI wrapper so the app can
reliably inspect and edit environment variables/tokens across Windows and WSL,
including:

- Windows process vars, User/Machine registry vars, and PowerShell profile vars
- WSL `~/.bashrc` and `/etc/environment`
- Editable `.env` and `.env.*` files (Windows paths and WSL filesystem paths)
- Safe write flows: diff preview, auto backup, rollback, audit log
- Verified delivery in both source mode and packaged `dist/env-inspector.exe`

This plan also fixes existing path breakages in docs/build/spec
(`tools/env-inspector/...` references).

## Public Interfaces and Type Changes

### CLI surface (new stable interface)

Add subcommands in `env_inspector.py` (or a new package entrypoint) with
machine-readable JSON output:

1. `list`
2. `set`
3. `remove`
4. `export`
5. `backup`
6. `restore`

Add common flags:

- `--context windows|wsl:<distro>`
- `--source process|windows_user|windows_machine|powershell_profile|wsl_bashrc|wsl_etc_environment|dotenv`
- `--target` repeated target identifiers for multi-target writes
- `--root <path>` for Windows-side dotenv scan
- `--wsl-path <path>` with `--distro <name>` for WSL filesystem dotenv scan
- `--include-raw-secrets` optional (default masked)
- `--output json|csv|table`

### Data model updates

Extend `EnvRecord` to include:

- `source_path` (file/registry path)
- `context` (`windows` or `wsl:<distro>`)
- `precedence_rank`
- `writable` and `requires_privilege`
- `last_error` (optional, per-source read/write status)

Add operation result schema:

- `operation_id`
- `target`
- `action`
- `success`
- `backup_path` (if write attempted)
- `diff_preview`
- `error_message`

### GUI behavior changes

- Add top context dropdown (`Windows` + each WSL distro)
- Add multi-target picker dialog for Set/Remove
- Add diff-preview confirm dialog before any write
- Add dotenv target chooser when duplicate key appears in multiple files
- Add WSL filesystem scanner controls (distro + path + depth)
- Keep secrets masked by default

## Implementation Plan

### Phase 1: Stabilize current project entry/build paths

1. Update `README.md` paths from `tools/env-inspector/...` to local repo-root
   paths.
2. Update `build-windows-exe.ps1` to install/run local files
   (`requirements-build.txt`, `env_inspector.py`).
3. Update `env-inspector.spec` script path to local `env_inspector.py`.
4. Add a quick validation section in `README.md` with exact commands for source
   run and build run.

### Phase 2: Create CLI core architecture

1. Introduce module split while keeping `env_inspector.py` as main entrypoint.
2. Create provider modules for each source type.
3. Create writer modules for each writable target.
4. Add unified command dispatcher for `list/set/remove/export/backup/restore`.
5. Ensure GUI calls CLI-core functions (direct import or subprocess contract),
   not ad-hoc inline logic.

### Phase 3: Source providers (read flows)

1. Keep existing process/registry/bashrc providers.
2. Add PowerShell profile provider:

- Current user profile
- All users profile (read/edit behavior as selected)

1. Add WSL `/etc/environment` provider per distro.
2. Add WSL filesystem dotenv provider with explicit distro+path scanning.
3. Add context-based effective-value resolver:

- Windows context precedence
- Per-distro WSL context precedence

### Phase 4: Write engine with safety

1. Implement diff generation for each target before write.
2. Implement backup creation before write for every file/target.
3. Store backups in project folder under `./.env-inspector-state/backups`.
4. Enforce retention: keep last 20 backups per target.
5. Implement restore command from backup id/path.
6. Implement audit log in project folder under
   `./.env-inspector-state/audit.log`.
7. Write masking rules in logs (no raw secret values).
8. Implement WSL privileged write strategy for `/etc/environment`:

- Try `wsl.exe -d <distro> -u root ...`
- If that fails, attempt sudo-based fallback
- Return explicit actionable error when both fail

### Phase 5: GUI integration for new capability

1. Add context dropdown at top of UI.
2. Add effective-value panel for selected key in current context.
3. Add multi-target picker dialog for Set/Remove actions.
4. Add diff-preview confirmation dialog with per-target diff blocks.
5. Add dotenv target file selector when multiple matches exist.
6. Add WSL path scan controls (distro/path/depth).
7. Keep existing secret masking toggle and only-secret filter behavior.

### Phase 6: Export support

1. Add JSON export of current filtered view with source metadata.
2. Add CSV export with source metadata.
3. Default exports to masked secrets.
4. Add explicit opt-in for raw secrets in export path only.

### Phase 7: Tests and validation

1. Add pytest suite folder.
2. Add parser tests:

- dotenv parser
- PowerShell profile parser
- bashrc export parser
- `/etc/environment` parser

1. Add writer tests:

- upsert/remove semantics
- quote handling
- newline preservation
- backup creation and retention

1. Add privilege strategy tests with mocked subprocess:

- root path success
- root fail + sudo success
- both fail

1. Add context precedence tests:

- Windows effective value
- WSL distro-specific effective value

1. Add GUI logic tests where feasible via isolated logic functions.
2. Add manual Windows validation checklist in README:

- Source mode run
- EXE run
- Read across all selected sources
- Write/remove with diff, backup, rollback, audit verification

### Phase 8: Packaging and verification gate

1. Build `dist/env-inspector.exe` using updated script.
2. Run source mode and EXE mode on Windows.
3. Execute checklist for:

- Read coverage
- Write coverage
- Backup/restore
- Export
- Context effective preview

1. Record known limitations and troubleshooting steps in README.

## Test Cases and Scenarios

1. Windows registry write:

- Set/remove in User scope.
- Set/remove in Machine scope with elevation path.
- Validate persistence and refresh.

1. PowerShell profile edit:

- Add new variable line.
- Update existing variable.
- Remove variable.
- Verify file integrity and backup created.

1. WSL bashrc edit:

- Set/remove across selected distros.
- Confirm helper distros default unchecked behavior remains.

1. WSL `/etc/environment` edit:

- Root invocation succeeds.
- Root fails, sudo fallback succeeds.
- Both fail with clear error and no silent corruption.

1. Dotenv editing:

- Single-file update.
- Duplicate key in multiple files with explicit target selection.
- Removal from selected file only.
- WSL filesystem dotenv edit path.

1. Backup/restore:

- Backup generated before each write.
- Rotation keeps last 20 per target.
- Restore recovers exact previous content.

1. Export:

- JSON/CSV include source metadata.
- Secret masking default enforced.
- Raw secret export requires explicit opt-in.

1. Effective value context:

- Same key across multiple sources resolves differently by selected context.
- UI preview matches resolver output.

## Assumptions and Defaults

- Full functionality target is Windows host with WSL integration.
- Linux native mode remains secondary and can stay read-only/minimal where
  Windows APIs are required.
- Secrets are masked by default in UI, logs, and exports.
- Backups and audit logs are stored in project folder:
  `./.env-inspector-state/`.
- `/etc/environment` writes use `wsl -u root` first, then sudo fallback
  automatically.
- `.env` files are editable and target file selection is always explicit when
  ambiguous.
- Multi-target writes are supported via target picker, with diff preview
  required before apply.
- Delivery is complete only after both source mode and EXE mode pass the
  verification checklist.
