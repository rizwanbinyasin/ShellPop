from urllib.parse import quote
from binascii import hexlify
import base64


def to_urlencode(data):
    """
    URL-encode a byte stream, plus extra replacements.
    """
    additional = [".", "/"]

    # Ensure bytes → string before quote
    if isinstance(data, bytes):
        data = data.decode('latin1')  # or 'utf-8'; use 'latin1' to preserve raw bytes if needed

    data = quote(data)

    for each in additional:
        encoded = hexlify(each.encode()).decode()
        data = data.replace(each, "%" + encoded)

    return data


def to_unicode(data):
    """
    Convert string to UTF-16LE byte sequence (as bytes).
    This is what PowerShell expects for "Unicode" strings.
    Returns bytes, not a str with manual nulls.
    """
    if isinstance(data, str):
        return data.encode('utf-16le')
    return data  # assume already bytes


def powershell_base64(data, unicode_encoding=True):
    """
    Return PowerShell-compatible Base64 (UTF-16LE → Base64)
    """
    if unicode_encoding:
        # Encode string directly to UTF-16LE bytes
        if isinstance(data, str):
            data = data.encode('utf-16le')
        # If already bytes, assume it's correct (rare)
    else:
        if isinstance(data, str):
            data = data.encode('utf-8')  # or 'ascii'

    return base64.b64encode(data).decode()


def xor(data, key):
    """
    XOR encoder (Python 3 safe)
    """
    if not isinstance(key, int):
        return None

    if isinstance(data, str):
        data = data.encode('utf-8')  # or 'latin1' if raw bytes expected

    output = bytes([b ^ key for b in data])
    return output