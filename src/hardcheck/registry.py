"""Registry of independently implemented security checks."""

from typing import TypeVar

from hardcheck.checks.base import BaseCheck

CheckClass = TypeVar("CheckClass", bound=type[BaseCheck])
_REGISTERED: dict[str, type[BaseCheck]] = {}


def register_check(check_class: CheckClass) -> CheckClass:
    """Register a check by its unique identifier."""
    if check_class.check_id in _REGISTERED:
        raise ValueError(f"Duplicate check ID: {check_class.check_id}")
    _REGISTERED[check_class.check_id] = check_class
    return check_class


def get_registered_checks() -> tuple[type[BaseCheck], ...]:
    """Return check classes in deterministic identifier order."""
    return tuple(_REGISTERED[key] for key in sorted(_REGISTERED))
