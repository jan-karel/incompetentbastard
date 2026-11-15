#!/usr/bin/env python3
"""CLI: verrijk de bevindingen-templates met de OWASP Top 10 (2025) catalogus.

Gebruik:
    python scripts/import_owasp2025.py /pad/naar/owasp-top10-2025.sqlite3 [--no-enrich]

--no-enrich maakt alleen nieuwe templates aan en raakt bestaande niet aan.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from meuk.flask.owasp_import import import_owasp2025  # noqa: E402


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    enrich = '--no-enrich' not in argv[2:]
    if not os.path.exists(path):
        print('Bestand niet gevonden: {}'.format(path))
        return 1
    app = create_app()
    with app.app_context():
        stats = import_owasp2025(path, enrich=enrich)
    print('Klaar: {created} aangemaakt, {enriched} verrijkt, '
          '{skipped} overgeslagen (van {total}).'.format(**stats))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
