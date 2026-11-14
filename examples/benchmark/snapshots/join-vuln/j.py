# Synthetic example code, written for this repository's docs. Not real.
import os
import posixpath

def join_under(base, *names):
    """Join untrusted names under base."""
    parts = [base]
    for name in names:
        if name != "":
            name = posixpath.normpath(name)
        if (
            any(sep in name for sep in ALT)
            or os.path.isabs(name)
            or name == ".."
            or name.startswith("../")
        ):
            return None
        parts.append(name)
    return posixpath.join(*parts)
