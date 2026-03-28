from __future__ import absolute_import, division

import uuid
from pathlib import Path
from typing import Any, List, Tuple

from .models import OperationResult
from .parsing import (
    remove_export,
    remove_key_value,
    remove_powershell_env,
    upsert_export,
    upsert_key_value,
    upsert_powershell_env,
    validate_env_key,
    validate_env_value,
)
from .path_policy import parse_scoped_dotenv_target
from .secrets import looks_secret
from .service_models import ShellMutationRequest, TargetOperationBatch, TargetOperationRequest
from .service_ops import (
    OperationResultInput,
    normalize_target_operation_batch as _normalize_target_operation_batch_helper,
    normalize_target_operation_request as _normalize_target_operation_request_helper,
    operation_result as _operation_result_helper,
)
from .service_privileged import (
    write_linux_etc_environment_with_privilege as _write_linux_etc_environment_with_privilege_helper,
)
from .service_wsl import (
    parse_wsl_dotenv_target as _parse_wsl_dotenv_target_helper,
    resolve_wsl_target as _resolve_wsl_target_helper,
)

TARGET_WINDOWS_USER = "windows:user"
TARGET_WINDOWS_MACHINE = "windows:machine"
TARGET_LINUX_BASHRC = "linux:bashrc"
TARGET_LINUX_ETC_ENV = "linux:etc_environment"
TARGET_POWERSHELL_CURRENT_USER = "powershell:current_user"
TARGET_POWERSHELL_ALL_USERS = "powershell:all_users"
DOTENV_TARGET_PREFIX = "dotenv:"
WSL_DOTENV_TARGET_PREFIX = "wsl_dotenv:"
LINUX_ETC_ENV_PATH = "/etc/environment"


def _service_module():
    from . import service as service_module

    return service_module


def _coerce_target_request(*args: Any, **kwargs: Any) -> TargetOperationRequest:
    request_data = _normalize_target_operation_request_helper(*args, **kwargs)
    return TargetOperationRequest(
        target=request_data["target"],
        key=request_data["key"],
        value=request_data["value"],
        action=request_data["action"],
        scope_roots=request_data["scope_roots"],
    )


def _coerce_target_batch(*args: Any, **kwargs: Any) -> TargetOperationBatch:
    request_data = _normalize_target_operation_batch_helper(*args, **kwargs)
    return TargetOperationBatch(
        action=request_data["action"],
        key=request_data["key"],
        value=request_data["value"],
        targets=request_data["targets"],
        scope_roots=request_data["scope_roots"],
    )


def powershell_profile_path(self, target: str) -> Path:
    current, all_users = self.get_powershell_profile_paths()
    if target == TARGET_POWERSHELL_CURRENT_USER:
        return current
    if target == TARGET_POWERSHELL_ALL_USERS:
        return all_users
    raise RuntimeError(f"Unsupported PowerShell target: {target}")


def update_dotenv_file(
    self,
    *args: Any,
    apply_changes: bool,
    **kwargs: Any,
) -> Tuple[str, str, str | None, bool, str | None]:
    request = _coerce_target_request(*args, **kwargs)
    scoped = parse_scoped_dotenv_target(request.target, roots=list(request.scope_roots))
    path = self._validate_path_in_roots(scoped.path, list(scoped.roots), label="dotenv target path")
    before = _service_module()._read_text_if_exists(path)
    after = (
        upsert_key_value(before, request.key, request.value or "", quote=False)
        if request.action == "set"
        else remove_key_value(before, request.key)
    )
    if apply_changes:
        self._write_scoped_text_file(
            candidate_path=scoped.path,
            allowed_roots=scoped.roots,
            text=after,
            label="dotenv target path",
        )
    return before, after, str(path), False, None


def mutate_shell_content(before: str, request: ShellMutationRequest) -> str:
    if request.action != "set":
        if request.style == "export":
            return remove_export(before, request.key)
        return remove_key_value(before, request.key)
    if request.style == "export":
        return upsert_export(before, request.key, request.value or "")
    return upsert_key_value(before, request.key, request.value or "", quote=False)


def update_linux_file(
    self,
    *args: Any,
    apply_changes: bool,
    **kwargs: Any,
) -> Tuple[str, str, str | None, bool, str | None]:
    request = _coerce_target_request(*args, **kwargs)
    if request.target == TARGET_LINUX_BASHRC:
        bashrc_path = Path.home() / ".bashrc"
        before = _service_module()._read_text_if_exists(bashrc_path)
        after = self._mutate_shell_content(before, ShellMutationRequest(request.key, request.value, request.action, "export"))
        if apply_changes:
            self._write_text_file(bashrc_path, after, ensure_parent=True)
        return before, after, str(bashrc_path), False, None

    if request.target == TARGET_LINUX_ETC_ENV:
        etc_path = self._linux_etc_environment_path()
        before = _service_module()._read_text_if_exists(etc_path)
        after = self._mutate_shell_content(
            before,
            ShellMutationRequest(request.key, request.value, request.action, "key_value"),
        )
        if apply_changes:
            self._write_linux_etc_environment_with_privilege(after)
        return before, after, LINUX_ETC_ENV_PATH, True, None

    raise RuntimeError(f"Unsupported Linux target: {request.target}")


def write_linux_etc_environment_with_privilege(self, text: str) -> None:
    _write_linux_etc_environment_with_privilege_helper(
        fixed_path=LINUX_ETC_ENV_PATH,
        expected_path=self._LINUX_ETC_ENV_PATH,
        text=text,
        write_text_file=lambda path, payload: self._write_text_file(path, payload, ensure_parent=False),
        which_fn=_service_module().which,
        run_fn=_service_module().run,
    )


def parse_wsl_dotenv_target(self, target: str) -> Tuple[str, str]:
    return _parse_wsl_dotenv_target_helper(
        target,
        prefix=WSL_DOTENV_TARGET_PREFIX,
        validate_distro_name_fn=self._validate_wsl_distro_name,
        validate_dotenv_path_fn=self._validate_wsl_dotenv_path,
    )


def resolve_wsl_target(self, target: str) -> Tuple[str, str, str, bool]:
    return _resolve_wsl_target_helper(
        target,
        dotenv_prefix=WSL_DOTENV_TARGET_PREFIX,
        validate_distro_name_fn=self._validate_wsl_distro_name,
        parse_wsl_dotenv_target_fn=self._parse_wsl_dotenv_target,
        linux_etc_env_path=self._LINUX_ETC_ENV_PATH,
    )


def update_wsl_file(
    self,
    *args: Any,
    apply_changes: bool,
    **kwargs: Any,
) -> Tuple[str, str, str | None, bool, str | None]:
    request = _coerce_target_request(*args, **kwargs)
    distro, path, style, requires_priv = self._resolve_wsl_target(request.target)
    before = self.wsl.read_file(distro, path)
    after = self._mutate_shell_content(before, ShellMutationRequest(request.key, request.value, request.action, style))

    if apply_changes:
        writer = self.wsl.write_file_with_privilege if requires_priv else self.wsl.write_file
        writer(distro, path, after)

    return before, after, f"{distro}:{path}", requires_priv, None


def update_powershell_file(
    self,
    *args: Any,
    apply_changes: bool,
    **kwargs: Any,
) -> Tuple[str, str, str | None, bool, str | None]:
    request = _coerce_target_request(*args, **kwargs)
    profile, allowed_roots, requires_priv = self._powershell_target_path_and_roots(request.target)
    safe_profile = self._validate_path_in_roots(profile, allowed_roots, label="PowerShell profile path")
    before = _service_module()._read_text_if_exists(safe_profile)
    after = (
        upsert_powershell_env(before, request.key, request.value or "")
        if request.action == "set"
        else remove_powershell_env(before, request.key)
    )
    if apply_changes:
        self._write_text_file(safe_profile, after, ensure_parent=True)
    return before, after, str(safe_profile), requires_priv, None


def file_update(
    self,
    *args: Any,
    apply_changes: bool,
    **kwargs: Any,
) -> Tuple[str, str, str | None, bool, str | None]:
    request = _coerce_target_request(*args, **kwargs)
    if request.target.startswith(DOTENV_TARGET_PREFIX):
        return self._update_dotenv_file(request=request, apply_changes=apply_changes)
    if request.target.startswith("linux:"):
        return self._update_linux_file(request=request, apply_changes=apply_changes)
    if request.target.startswith("wsl"):
        return self._update_wsl_file(request=request, apply_changes=apply_changes)
    if request.target.startswith("powershell:"):
        return self._update_powershell_file(request=request, apply_changes=apply_changes)
    raise RuntimeError(f"Unsupported target: {request.target}")


def plan_target_operation(
    self,
    *args: Any,
    apply_changes: bool,
    **kwargs: Any,
) -> Tuple[str, str, str | None, bool, str | None]:
    request = _coerce_target_request(*args, **kwargs)
    if request.target in {TARGET_WINDOWS_USER, TARGET_WINDOWS_MACHINE}:
        return self._registry_write(request=request, apply_changes=apply_changes)
    return self._file_update(request=request, apply_changes=apply_changes)


def validate_target_for_operation(self, target: str, *, scope_roots: List[Path]) -> None:
    if target in {
        TARGET_WINDOWS_USER,
        TARGET_WINDOWS_MACHINE,
        TARGET_LINUX_BASHRC,
        TARGET_LINUX_ETC_ENV,
        TARGET_POWERSHELL_CURRENT_USER,
        TARGET_POWERSHELL_ALL_USERS,
    }:
        return
    if target.startswith(DOTENV_TARGET_PREFIX):
        parse_scoped_dotenv_target(target, roots=scope_roots)
        return
    if target.startswith(WSL_DOTENV_TARGET_PREFIX):
        self._parse_wsl_dotenv_target(target)
        return
    if target.startswith("wsl:"):
        self._resolve_wsl_target(target)
        return
    raise RuntimeError(f"Unsupported target: {target}")


def preview_target_diff(self, *args: Any, **kwargs: Any) -> Tuple[str, str]:
    request = _coerce_target_request(*args, **kwargs)
    self._validate_target_for_operation(request.target, scope_roots=list(request.scope_roots))
    before, after, _, _, _ = self._plan_target_operation(request=request, apply_changes=False)
    return before, self._diff(before, after, request.target)


def apply_target_operation(self, *args: Any, before: str, **kwargs: Any) -> str:
    request = _coerce_target_request(*args, **kwargs)
    backup_path = str(self.backup_mgr.backup_text(request.target, before))
    self._plan_target_operation(request=request, apply_changes=True)
    return backup_path


def execute_target_operation(
    self,
    *args: Any,
    preview_only: bool,
    secret_operation: bool,
    **kwargs: Any,
) -> OperationResult:
    request = _coerce_target_request(*args, **kwargs)
    operation_id = f"{request.action}-{uuid.uuid4().hex[:10]}"
    value_masked = self._masked_value(secret_operation=secret_operation, value=request.value)
    backup_path: str | None = None
    diff_preview = ""
    try:
        before, diff_preview = self._preview_target_diff(request)
        if not preview_only:
            backup_path = self._apply_target_operation(request, before=before)
        return _operation_result_helper(
            OperationResultInput(
                operation_id=operation_id,
                target=request.target,
                action=request.action,
                success=True,
                backup_path=backup_path,
                preview_only=preview_only,
                diff_preview=diff_preview,
                error_message=None,
                value_masked=value_masked,
            )
        )
    except self._operation_error_types() as exc:
        return _operation_result_helper(
            OperationResultInput(
                operation_id=operation_id,
                target=request.target,
                action=request.action,
                success=False,
                backup_path=backup_path,
                preview_only=False,
                diff_preview=diff_preview,
                error_message=str(exc),
                value_masked=value_masked,
            )
        )


def apply(
    self,
    *args: Any,
    preview_only: bool = False,
    **kwargs: Any,
) -> List[OperationResult]:
    request = _coerce_target_batch(*args, **kwargs)
    validate_env_key(request.key)
    if request.action == "set":
        validate_env_value(request.value or "")

    secret_operation = looks_secret(request.key, request.value or "")
    resolved_scope_roots = self._effective_scope_roots(request.scope_roots)
    results: List[OperationResult] = []
    for target in request.targets:
        target_request = TargetOperationRequest(
            target=target,
            key=request.key,
            value=request.value,
            action=request.action,
            scope_roots=resolved_scope_roots,
        )
        result = self._execute_target_operation(
            target_request,
            preview_only=preview_only,
            secret_operation=secret_operation,
        )
        self.audit.log(self._audit_safe_result(result, redact=secret_operation))
        results.append(result)
    return results
