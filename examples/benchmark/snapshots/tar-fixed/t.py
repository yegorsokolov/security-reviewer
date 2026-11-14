# Synthetic example code, written for this repository's docs. Not real.
import os

def target_inside(archive, info):
    name = os.path.normpath(os.path.join(os.path.dirname(info.name),
                                         info.linkname))
    try:
        archive.getmember(name)
        return True
    except KeyError:
        return False

def unpack(archive, dest):
    for member in archive.getmembers():
        target = os.path.join(dest, member.name)
        if member.isdir():
            os.makedirs(target, exist_ok=True)
        elif member.issym():
            if not target_inside(archive, member):
                raise ValueError("escapes")
            archive._extract_member(member, target)
