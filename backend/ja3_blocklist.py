"""
JA3 fingerprint matching against a known-bad list.

tls_features.py already computes a JA3 hash for every TLS ClientHello it
sees. Until now that hash was only shown as evidence; it never changed a
verdict. This module makes it a detection signal: if a client's JA3 hash
appears in ja3_blocklist.csv, that's a match against a known-malicious
TLS client fingerprint, which is stronger evidence than the structural
"sparse ClientHello" heuristic.

Honesty note: NO real threat-intel hashes are bundled. Populate
ja3_blocklist.csv from a feed you trust, for example abuse.ch's SSLBL
JA3 fingerprint list, then restart the backend. The one entry shipped
in the file is a LAB-DEMO entry for ja3_demo.pcap, so the matching path
can be demonstrated end to end without inventing malware hashes.

Entries may be client JA3 hashes or server JA3S hashes (both are 32-char
MD5s); put which one in the label. detector.py checks both.

File format (ja3_blocklist.csv), one per line, '#' starts a comment:
    <32-char md5>,<label>
"""

import os

BLOCKLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ja3_blocklist.csv")

_cache = {"mtime": None, "entries": {}}


def _load():
    try:
        mtime = os.path.getmtime(BLOCKLIST_PATH)
    except OSError:
        _cache["mtime"], _cache["entries"] = None, {}
        return _cache["entries"]

    if _cache["mtime"] == mtime:
        return _cache["entries"]

    entries = {}
    with open(BLOCKLIST_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ja3, _, label = line.partition(",")
            ja3 = ja3.strip().lower()
            if len(ja3) == 32:
                entries[ja3] = label.strip() or "unlabelled"

    _cache["mtime"], _cache["entries"] = mtime, entries
    return entries


def lookup_ja3(ja3_hash):
    """Returns the blocklist label for this JA3 hash, or None. Reloads the
    file automatically when it changes, so no restart is needed to add entries."""
    if not ja3_hash:
        return None
    return _load().get(ja3_hash.lower())
