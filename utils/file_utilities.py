import hashlib


def get_file_md5(filepath: str) -> str:
    """Get the MD5 hash of a file

    Args:
        filepath: The path to the file

    Returns:
        The MD5 hash of the file"""
    md5_hash = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest().upper()


def format_file_size(size: int | float, suffix: str = "B") -> str:
    """Convert file size to human readable format

    Args:
        size: The size of the file
        suffix: The suffix to use for the file size

    Returns:
        The human readable file size"""
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(size) < 1024.0:
            return f"{size:3.1f}{unit}{suffix}"
        size /= 1024.0
    return f"{size:.1f}Yi{suffix}"
