from pathlib import Path
SUPPORTED={'E01':'Expert Witness Format','EX01':'Expert Witness Format','RAW':'Raw disk image','DD':'Raw disk image','AFF':'Advanced Forensic Format','AFF4':'Advanced Forensic Format'}
def support_status(filename):
    ext=Path(filename).suffix.lstrip('.').upper()
    return ext, ext in SUPPORTED, SUPPORTED.get(ext,'Unsupported forensic image format')
