# Synthetic example code, written for this repository's docs. Not real.
import os

def unpack(archive, dest):
    for member in archive.getmembers():
        target = os.path.join(dest, member.name)
        if member.isdir():
            os.makedirs(target, exist_ok=True)
        elif member.issym():
            try:
                archive._extract_member(member, target)
            except Exception:
                continue
        else:
            archive.extractfile(member)
