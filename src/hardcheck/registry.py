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
    load_builtin_checks()
    return tuple(_REGISTERED[key] for key in sorted(_REGISTERED))


def load_builtin_checks() -> None:
    """Load fixed built-in implementations, without filesystem discovery/plugins."""
    from hardcheck.checks.filesystem import (
        PasswdPermissionsCheck,
        ShadowPermissionsCheck,
        TmpStickyCheck,
    )
    from hardcheck.checks.firewall import FirewallCheck
    from hardcheck.checks.listeners import LegacyListenerCheck
    from hardcheck.checks.password_policy import PasswordAgeCheck, PasswordLengthCheck
    from hardcheck.checks.services import LegacyServiceCheck
    from hardcheck.checks.ssh import (
        SshEmptyPasswordsDisabledCheck,
        SshMaxAuthTriesCheck,
        SshPasswordAuthenticationDisabledCheck,
        SshRootLoginDisabledCheck,
    )
    from hardcheck.checks.sysctl import AslrCheck, DmesgRestrictCheck, IpForwardingCheck
    from hardcheck.checks.users import EmptyPasswordCheck, RootUidCheck
    from hardcheck.checks.world_writable import WorldWritableEtcCheck

    implementations = (
        SshRootLoginDisabledCheck,
        SshPasswordAuthenticationDisabledCheck,
        SshMaxAuthTriesCheck,
        SshEmptyPasswordsDisabledCheck,
        EmptyPasswordCheck,
        RootUidCheck,
        PasswordAgeCheck,
        PasswordLengthCheck,
        PasswdPermissionsCheck,
        ShadowPermissionsCheck,
        TmpStickyCheck,
        WorldWritableEtcCheck,
        FirewallCheck,
        LegacyListenerCheck,
        IpForwardingCheck,
        AslrCheck,
        DmesgRestrictCheck,
        LegacyServiceCheck,
    )
    for check in implementations:
        if _REGISTERED.get(check.check_id) is not check:
            register_check(check)
