# biovault/output.py
# Console output that survives non-UTF-8 terminals.
# Windows consoles default to cp1252, which cannot encode the emoji used
# throughout this tool — printing them raised UnicodeEncodeError and took
# down encode/decode entirely.

import sys


def safe_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, 'encoding', None) or 'ascii'
        cleaned = [
            str(a).encode(encoding, errors='replace').decode(encoding, errors='replace')
            for a in args
        ]
        print(*cleaned, **kwargs)
