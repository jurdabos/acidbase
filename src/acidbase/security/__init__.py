"""
Cross-platform security-patching automation.

Provides helpers to discover repositories affected by a vulnerable
dependency, patch them via uv, publish the fix (push or PR), and verify that
Dependabot alerts clear afterwards. Works the same on Windows pwsh and on
Linux/WSL bash.
"""

from acidbase.security.alerts import (
    AlertSettingResult,
    DependabotAlert,
    check_repo_setting,
    enable_automated_security_fixes,
    enable_vulnerability_alerts,
    fetch_alerts_for_owner,
    fetch_alerts_for_repo,
)
from acidbase.security.patcher import PatchResult, patch_repo
from acidbase.security.profiles import Profile, load_config, resolve_profile
from acidbase.security.publisher import PrStrategy, PublishStrategy, PushStrategy
from acidbase.security.scanner import VulnerableHit, discover_affected_repos
from acidbase.security.verifier import verify_remote_bump

__all__ = [
    "AlertSettingResult",
    "DependabotAlert",
    "PatchResult",
    "PrStrategy",
    "Profile",
    "PublishStrategy",
    "PushStrategy",
    "VulnerableHit",
    "check_repo_setting",
    "discover_affected_repos",
    "enable_automated_security_fixes",
    "enable_vulnerability_alerts",
    "fetch_alerts_for_owner",
    "fetch_alerts_for_repo",
    "load_config",
    "patch_repo",
    "resolve_profile",
    "verify_remote_bump",
]
