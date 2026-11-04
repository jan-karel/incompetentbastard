"""Buffer Overflow workspace — cyclisch patroon + offset, badchar-generator,
en return-adres helper (little-endian).

De patroon-/offsetlogica is compatibel met Metasploit's pattern_create /
pattern_offset (sets A-Z, a-z, 0-9), zodat EIP/EBP-waarden direct te vertalen
zijn naar een offset. Uitsluitend lokale berekeningen, geen externe tools.
"""

import re

from flask import Blueprint, request, jsonify, render_template

from meuk.flask.security import require_dashboard_access

bof_bp = Blueprint('bof_bp', __name__, template_folder='html')

_SETS = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz', '0123456789')
_MAX_PATTERN = len(_SETS[0]) * len(_SETS[1]) * len(_SETS[2]) * 3  # 20280


@bof_bp.before_request
def _check_dashboard_access():
    require_dashboard_access()


def pattern_create(length):
    """Genereer een cyclisch (De Bruijn-achtig) patroon zoals msf-pattern_create."""
    length = max(0, min(int(length), _MAX_PATTERN))
    out = []
    c0 = c1 = c2 = 0
    while len(out) < length:
        out.append(_SETS[0][c0])
        if len(out) < length:
            out.append(_SETS[1][c1])
        if len(out) < length:
            out.append(_SETS[2][c2])
        c2 += 1
        if c2 == len(_SETS[2]):
            c2 = 0
            c1 += 1
            if c1 == len(_SETS[1]):
                c1 = 0
                c0 += 1
                if c0 == len(_SETS[0]):
                    c0 = 0
    return ''.join(out[:length])


def _query_to_substring(query):
    """Zet een zoekterm om naar de ASCII-substring die in het patroon staat.

    Accepteert een hex-registerwaarde (0x37654136 of 37654136), die als
    little-endian bytes naar ASCII wordt vertaald, of een letterlijke tekst.
    """
    q = (query or '').strip()
    if not q:
        return ''
    hexval = q[2:] if q.lower().startswith('0x') else q
    if re.fullmatch(r'[0-9a-fA-F]{2,16}', hexval) and len(hexval) % 2 == 0:
        try:
            val = int(hexval, 16)
            nbytes = len(hexval) // 2
            packed = val.to_bytes(nbytes, 'little')
            return packed.decode('latin-1')
        except (ValueError, OverflowError):
            pass
    return q


def pattern_offset(query, length=_MAX_PATTERN):
    """Zoek de offset van een registerwaarde/substring in het patroon.

    Returns de offset (int) of None als niet gevonden.
    """
    sub = _query_to_substring(query)
    if not sub:
        return None
    pattern = pattern_create(length)
    idx = pattern.find(sub)
    return idx if idx >= 0 else None


def badchar_bytes(exclude):
    """Geef de bytes 0x01..0xff minus de uitgesloten bytes.

    `exclude` is een iterable van ints (0-255).
    """
    excl = set(int(x) & 0xFF for x in exclude)
    excl.add(0x00)  # nulbyte altijd uitsluiten
    return bytes(b for b in range(1, 256) if b not in excl)


def _parse_badchar_list(raw):
    """Parse '00,0a,0d' of '\\x00\\x0a' of '00 0a 0d' naar een lijst ints."""
    if not raw:
        return []
    tokens = re.findall(r'[0-9a-fA-F]{2}', raw)
    return [int(t, 16) for t in tokens]


def format_bytes(bs):
    """Geef meerdere representaties van een bytereeks."""
    hexpairs = [format(b, '02x') for b in bs]
    return {
        'escaped': ''.join('\\x' + h for h in hexpairs),
        'python': 'b"' + ''.join('\\x' + h for h in hexpairs) + '"',
        'c_array': '{ ' + ', '.join('0x' + h for h in hexpairs) + ' }',
        'spaced': ' '.join(hexpairs),
        'count': len(bs),
    }


def retaddr_bytes(address, arch='x86'):
    """Zet een adres om naar little-endian bytes (\\x..) voor x86 (4) of x64 (8)."""
    a = (address or '').strip()
    hexval = a[2:] if a.lower().startswith('0x') else a
    val = int(hexval, 16)
    nbytes = 8 if arch == 'x64' else 4
    packed = val.to_bytes(nbytes, 'little')
    return packed


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bof_bp.route('/dashboard/bof', methods=['GET'])
def bof_dashboard():
    return render_template('bof.html')


@bof_bp.route('/api/bof/pattern', methods=['GET'])
def api_pattern():
    try:
        length = int(request.args.get('length', 0))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'ongeldige lengte'}), 400
    if length < 1 or length > _MAX_PATTERN:
        return jsonify({'ok': False, 'error': 'lengte buiten bereik (1..{})'.format(_MAX_PATTERN)}), 400
    return jsonify({'ok': True, 'length': length, 'pattern': pattern_create(length)})


@bof_bp.route('/api/bof/offset', methods=['GET'])
def api_offset():
    query = request.args.get('query', '')
    try:
        length = int(request.args.get('length', _MAX_PATTERN))
    except (TypeError, ValueError):
        length = _MAX_PATTERN
    off = pattern_offset(query, length)
    if off is None:
        return jsonify({'ok': False, 'error': 'niet gevonden in patroon', 'offset': None})
    return jsonify({'ok': True, 'offset': off, 'query': query})


@bof_bp.route('/api/bof/badchars', methods=['GET'])
def api_badchars():
    excl = _parse_badchar_list(request.args.get('exclude', ''))
    bs = badchar_bytes(excl)
    out = format_bytes(bs)
    out['ok'] = True
    out['excluded'] = ['%02x' % (b & 0xFF) for b in sorted(set(excl) | {0})]
    return jsonify(out)


@bof_bp.route('/api/bof/retaddr', methods=['GET'])
def api_retaddr():
    address = request.args.get('address', '')
    arch = request.args.get('arch', 'x86')
    if arch not in ('x86', 'x64'):
        arch = 'x86'
    try:
        packed = retaddr_bytes(address, arch)
    except (ValueError, OverflowError):
        return jsonify({'ok': False, 'error': 'ongeldig adres'}), 400
    out = format_bytes(packed)
    out['ok'] = True
    out['arch'] = arch
    return jsonify(out)
