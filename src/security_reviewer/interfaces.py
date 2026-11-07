"""Scanner and Validator interfaces.

These protocols are deliberately tiny and import nothing from GitHub or any
model provider, so any backend (static tool, AI model, human tooling) can
implement them.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Protocol, runtime_checkable

from .finding import Finding

#: Reads repo-relative POSIX ``path`` and returns its text, or None when the
#: file is unavailable (missing, unreadable, too large, outside the root).
ContextReader = Callable[[str], "str | None"]


@runtime_checkable
class Scanner(Protocol):
    """Produces schema_version 1 findings for a directory tree."""

    def scan(self, root) -> Iterable[Finding]:
        """Scan ``root`` (a path to a directory) and yield findings.

        Implementations must treat the tree as untrusted data and must emit
        findings in a deterministic order.
        """
        ...


@runtime_checkable
class Validator(Protocol):
    """Re-checks one finding against its source context."""

    def validate(self, finding: Finding, reader: ContextReader) -> Finding | None:
        """Return a new finding (via ``Finding.transition``) when the check
        changes its lifecycle state, or None when the finding is unchanged
        or not handled by this validator.
        """
        ...
