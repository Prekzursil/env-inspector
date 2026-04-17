"""Coverage tests for service_wsl.py — WSL target resolution edge cases."""

from __future__ import absolute_import, division
from tests.assertions import ensure

import pytest

from env_inspector_core.service_wsl import (
    validate_wsl_distro_name,
    validate_wsl_dotenv_path,
    parse_wsl_dotenv_target,
    _split_wsl_target,
    _resolve_standard_wsl_target,
    resolve_wsl_target,
)


# Line 10: validate_wsl_distro_name with null byte
def test_validate_wsl_distro_name_rejects_null() -> None:
    """validate_wsl_distro_name rejects names with null bytes."""
    with pytest.raises(RuntimeError, match="Unsupported WSL distro name"):
        validate_wsl_distro_name("bad\x00name")


# Line 10: validate_wsl_distro_name with colon
def test_validate_wsl_distro_name_rejects_colon() -> None:
    """validate_wsl_distro_name rejects names with colons."""
    with pytest.raises(RuntimeError, match="Unsupported WSL distro name"):
        validate_wsl_distro_name("bad:name")


# Line 10: validate_wsl_distro_name with empty
def test_validate_wsl_distro_name_rejects_empty() -> None:
    """validate_wsl_distro_name rejects empty names."""
    with pytest.raises(RuntimeError, match="Unsupported WSL distro name"):
        validate_wsl_distro_name("")


# Lines 36-37: parse_wsl_dotenv_target ValueError branch
def test_parse_wsl_dotenv_target_raises_on_missing_colon() -> None:
    """parse_wsl_dotenv_target raises when target has no colon separator."""
    with pytest.raises(RuntimeError, match="Unsupported WSL target"):
        parse_wsl_dotenv_target(
            "wsl_dotenv:no-colon-here",
            prefix="wsl_dotenv:",
            validate_distro_name_fn=validate_wsl_distro_name,
            validate_dotenv_path_fn=lambda p: p,
        )


# Line 44: _split_wsl_target with wrong number of parts
def test_split_wsl_target_rejects_bad_format() -> None:
    """_split_wsl_target raises when target doesn't have exactly 3 colon-separated parts."""
    with pytest.raises(RuntimeError, match="Unsupported WSL target"):
        _split_wsl_target("wsl:only_two")


# Line 66: resolve_wsl_target with no args
def test_resolve_wsl_target_requires_target() -> None:
    """resolve_wsl_target raises TypeError when called with no args."""
    with pytest.raises(TypeError, match="requires a target argument"):
        resolve_wsl_target(
            dotenv_prefix="wsl_dotenv:",
            validate_distro_name_fn=validate_wsl_distro_name,
            parse_wsl_dotenv_target_fn=lambda t: ("d", "/p"),
            linux_etc_env_path="/etc/environment",
        )


# Line 69: resolve_wsl_target with multiple positional args
def test_resolve_wsl_target_rejects_extra_args() -> None:
    """resolve_wsl_target raises TypeError with more than one positional arg."""
    with pytest.raises(TypeError, match="single positional target argument only"):
        resolve_wsl_target(
            "wsl:Ubuntu:bashrc", "extra",
            dotenv_prefix="wsl_dotenv:",
            validate_distro_name_fn=validate_wsl_distro_name,
            parse_wsl_dotenv_target_fn=lambda t: ("d", "/p"),
            linux_etc_env_path="/etc/environment",
        )


# Lines 76-77: resolve_wsl_target with unexpected kwargs
def test_resolve_wsl_target_rejects_unexpected_kwargs() -> None:
    """resolve_wsl_target raises TypeError on unexpected keyword arguments."""
    with pytest.raises(TypeError, match="Unexpected keyword argument"):
        resolve_wsl_target(
            "wsl:Ubuntu:bashrc",
            dotenv_prefix="wsl_dotenv:",
            validate_distro_name_fn=validate_wsl_distro_name,
            parse_wsl_dotenv_target_fn=lambda t: ("d", "/p"),
            linux_etc_env_path="/etc/environment",
            bogus="bad",
        )


# Line 81: resolve_wsl_target with dotenv prefix
def test_resolve_wsl_target_dotenv_prefix() -> None:
    """resolve_wsl_target handles dotenv prefix targets."""
    result = resolve_wsl_target(
        "wsl_dotenv:Ubuntu:/home/user/.env",
        dotenv_prefix="wsl_dotenv:",
        validate_distro_name_fn=validate_wsl_distro_name,
        parse_wsl_dotenv_target_fn=lambda t: ("Ubuntu", "/home/user/.env"),
        linux_etc_env_path="/etc/environment",
    )
    ensure(result == ("Ubuntu", "/home/user/.env", "key_value", False))


# Line 84: resolve_wsl_target with non-wsl prefix
def test_resolve_wsl_target_rejects_non_wsl_prefix() -> None:
    """resolve_wsl_target raises for targets not starting with wsl:."""
    with pytest.raises(RuntimeError, match="Unsupported WSL target"):
        resolve_wsl_target(
            "linux:bashrc",
            dotenv_prefix="wsl_dotenv:",
            validate_distro_name_fn=validate_wsl_distro_name,
            parse_wsl_dotenv_target_fn=lambda t: ("d", "/p"),
            linux_etc_env_path="/etc/environment",
        )


# _resolve_standard_wsl_target bashrc path
def test_resolve_standard_wsl_target_bashrc() -> None:
    """_resolve_standard_wsl_target returns bashrc config."""
    result = _resolve_standard_wsl_target(
        "wsl:Ubuntu:bashrc",
        validate_distro_name_fn=validate_wsl_distro_name,
        linux_etc_env_path="/etc/environment",
    )
    ensure(result == ("Ubuntu", "~/.bashrc", "export", False))


# _resolve_standard_wsl_target etc_environment path
def test_resolve_standard_wsl_target_etc_environment() -> None:
    """_resolve_standard_wsl_target returns etc_environment config."""
    result = _resolve_standard_wsl_target(
        "wsl:Ubuntu:etc_environment",
        validate_distro_name_fn=validate_wsl_distro_name,
        linux_etc_env_path="/etc/environment",
    )
    ensure(result == ("Ubuntu", "/etc/environment", "key_value", True))


# _resolve_standard_wsl_target unsupported suffix
def test_resolve_standard_wsl_target_unsupported() -> None:
    """_resolve_standard_wsl_target raises on unsupported suffix."""
    with pytest.raises(RuntimeError, match="Unsupported WSL target"):
        _resolve_standard_wsl_target(
            "wsl:Ubuntu:unknown",
            validate_distro_name_fn=validate_wsl_distro_name,
            linux_etc_env_path="/etc/environment",
        )


# validate_wsl_dotenv_path edge cases
def test_validate_wsl_dotenv_path_rejects_null_byte() -> None:
    """validate_wsl_dotenv_path rejects paths with null bytes."""
    with pytest.raises(RuntimeError):
        validate_wsl_dotenv_path("/home/\x00user/.env", path_error="bad path")


def test_validate_wsl_dotenv_path_rejects_relative() -> None:
    """validate_wsl_dotenv_path rejects relative paths."""
    with pytest.raises(RuntimeError):
        validate_wsl_dotenv_path("relative/.env", path_error="bad path")


def test_validate_wsl_dotenv_path_rejects_traversal() -> None:
    """validate_wsl_dotenv_path rejects paths with '..' traversal."""
    with pytest.raises(RuntimeError):
        validate_wsl_dotenv_path("/home/../etc/.env", path_error="bad path")


def test_validate_wsl_dotenv_path_rejects_non_dotenv_name() -> None:
    """validate_wsl_dotenv_path rejects files not named .env or .env.*."""
    with pytest.raises(RuntimeError):
        validate_wsl_dotenv_path("/home/user/config.txt", path_error="bad path")


def test_validate_wsl_dotenv_path_accepts_valid() -> None:
    """validate_wsl_dotenv_path accepts valid dotenv paths."""
    result = validate_wsl_dotenv_path("/home/user/.env", path_error="bad path")
    ensure(result == "/home/user/.env")

    result2 = validate_wsl_dotenv_path("/home/user/.env.local", path_error="bad path")
    ensure(result2 == "/home/user/.env.local")
