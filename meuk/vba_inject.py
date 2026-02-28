"""VBA macro injectie in Office Open XML documenten (.docx/.xlsx -> .docm/.xlsm).

Bouwt een valide vbaProject.bin (OLE/CFBF) met MS-OVBA compressie
en injecteert deze in een OOXML ZIP-archief. Alleen stdlib.
"""

import struct
import io
import os
import zipfile
import copy

# ---------------------------------------------------------------------------
# A. MS-OVBA 2.4.1 compressie
# ---------------------------------------------------------------------------

def _ovba_compress(data: bytes) -> bytes:
    """Comprimeer bytes volgens MS-OVBA 2.4.1 (sectie 2.4.1)."""
    out = io.BytesIO()
    out.write(b'\x01')  # CompressedChunkSignature
    idx = 0
    while idx < len(data):
        chunk_start = idx
        chunk_end = min(idx + 4096, len(data))
        chunk_data = data[chunk_start:chunk_end]
        compressed = _compress_chunk(chunk_data)
        idx = chunk_end
        out.write(compressed)
    return out.getvalue()


def _compress_chunk(data: bytes) -> bytes:
    """Comprimeer een enkele chunk (max 4096 bytes)."""
    if len(data) == 0:
        return b''

    # Probeer te comprimeren
    compressed_buf = io.BytesIO()
    src_idx = 0
    flags_pos = None
    flags_byte = 0
    bit_idx = 0

    while src_idx < len(data):
        if bit_idx == 0:
            flags_pos = compressed_buf.tell()
            compressed_buf.write(b'\x00')
            flags_byte = 0
            bit_idx = 0

        # Zoek langste match in eerder verwerkte data
        best_len = 0
        best_off = 0
        if src_idx > 0:
            # Bepaal de grootte van het offset/length veld
            compressed_end = src_idx
            bit_count = max(4, (compressed_end - 1).bit_length())
            max_len = (1 << (16 - bit_count)) + 2
            window_start = max(0, src_idx - (1 << bit_count))

            for j in range(window_start, src_idx):
                length = 0
                while (length < max_len and
                       src_idx + length < len(data) and
                       data[j + length] == data[src_idx + length]):
                    length += 1
                if length >= 3 and length > best_len:
                    best_len = length
                    best_off = src_idx - j

        if best_len >= 3:
            # Copy token
            compressed_end = src_idx
            bit_count = max(4, (compressed_end - 1).bit_length())
            length_bits = 16 - bit_count
            offset_encoded = best_off - 1
            length_encoded = best_len - 3
            token = (offset_encoded << length_bits) | length_encoded
            compressed_buf.write(struct.pack('<H', token))
            flags_byte |= (1 << bit_idx)
            src_idx += best_len
        else:
            # Literal byte
            compressed_buf.write(bytes([data[src_idx]]))
            src_idx += 1

        bit_idx += 1
        if bit_idx == 8:
            # Schrijf flags byte terug
            cur_pos = compressed_buf.tell()
            compressed_buf.seek(flags_pos)
            compressed_buf.write(bytes([flags_byte]))
            compressed_buf.seek(cur_pos)
            bit_idx = 0

    # Schrijf laatste flags byte
    if bit_idx > 0 and flags_pos is not None:
        cur_pos = compressed_buf.tell()
        compressed_buf.seek(flags_pos)
        compressed_buf.write(bytes([flags_byte]))
        compressed_buf.seek(cur_pos)

    compressed_data = compressed_buf.getvalue()

    # Altijd gecomprimeerd formaat gebruiken — voorkomt padding/truncatie
    # problemen bij decompressie van de laatste chunk (< 4096 bytes).
    # Chunk header: 12 bits size, 3 bits signature (0b011), 1 bit compressed flag
    size = len(compressed_data) - 1  # -1 want 0-based
    header = size | 0xB000  # signature=011, compressed=1
    return struct.pack('<H', header) + compressed_data


def _ovba_decompress(data: bytes) -> bytes:
    """Decomprimeer MS-OVBA gecomprimeerde data (sectie 2.4.1)."""
    if len(data) == 0:
        return b''
    if data[0:1] != b'\x01':
        raise ValueError("Ongeldig compressie signature byte")
    idx = 1
    out = bytearray()
    while idx < len(data):
        if idx + 2 > len(data):
            break
        header = struct.unpack_from('<H', data, idx)[0]
        idx += 2
        chunk_size = (header & 0x0FFF) + 1
        is_compressed = (header >> 15) & 1
        chunk_data = data[idx:idx + chunk_size]
        idx += chunk_size

        if not is_compressed:
            out.extend(chunk_data[:4096])
        else:
            _decompress_chunk(chunk_data, out)
    return bytes(out)


def _decompress_chunk(chunk: bytes, out: bytearray):
    """Decomprimeer een enkele gecomprimeerde chunk."""
    ci = 0
    chunk_start = len(out)
    while ci < len(chunk):
        flags = chunk[ci]
        ci += 1
        for bit in range(8):
            if ci >= len(chunk):
                break
            if flags & (1 << bit):
                # Copy token
                if ci + 2 > len(chunk):
                    break
                token = struct.unpack_from('<H', chunk, ci)[0]
                ci += 2
                decompressed_end = len(out) - chunk_start
                bit_count = max(4, (decompressed_end - 1).bit_length()) if decompressed_end > 1 else 4
                length_bits = 16 - bit_count
                length_mask = (1 << length_bits) - 1
                length = (token & length_mask) + 3
                offset = (token >> length_bits) + 1
                for _ in range(length):
                    src_pos = len(out) - offset
                    if src_pos < 0:
                        out.append(0)
                    else:
                        out.append(out[src_pos])
            else:
                # Literal
                out.append(chunk[ci])
                ci += 1


# ---------------------------------------------------------------------------
# B. dir stream builder (VBA project directory)
# ---------------------------------------------------------------------------

def _tlv(record_id: int, data: bytes) -> bytes:
    """Bouw een TLV record: 2-byte ID + 4-byte length + data."""
    return struct.pack('<HI', record_id, len(data)) + data


def _build_dir_stream(module_name: str, code_name: str) -> bytes:
    """Bouw de VBA project dir stream met TLV records."""
    buf = io.BytesIO()

    # PROJECTINFORMATION
    buf.write(_tlv(0x0001, struct.pack('<HH', 0x006A, 0x0002)))  # SysKind (Win32)
    buf.write(_tlv(0x0002, b'lcid'))      # CompatVersion placeholder
    buf.write(_tlv(0x0014, struct.pack('<I', 0x0409)))  # LCID
    buf.write(_tlv(0x0003, struct.pack('<I', 0x0409)))  # LCIDInvoke
    buf.write(_tlv(0x0004, struct.pack('<H', 0x0000)))  # CodePage (UTF-16 placeholder)

    # Project naam
    project_name = b'VBAProject'
    buf.write(_tlv(0x0006, project_name))  # PROJECTNAME

    # Doc string
    buf.write(_tlv(0x0005, b''))  # PROJECTDOCSTRING
    buf.write(_tlv(0x0040, b''))  # PROJECTDOCSTRING unicode

    # Help file
    buf.write(_tlv(0x0006, b''))  # PROJECTHELPFILEPATH (reuse id ok)
    buf.write(_tlv(0x003D, b''))  # PROJECTHELPFILEPATH unicode

    # Help context
    buf.write(_tlv(0x000E, struct.pack('<I', 0)))  # PROJECTHELPCONTEXT

    # Lib flags
    buf.write(_tlv(0x0008, struct.pack('<I', 0)))  # PROJECTLIBFLAGS

    # Version
    buf.write(_tlv(0x0009, struct.pack('<IH', 1, 1)))  # PROJECTVERSION

    # Constants
    buf.write(_tlv(0x000C, b''))  # PROJECTCONSTANTS
    buf.write(_tlv(0x003C, b''))  # PROJECTCONSTANTS unicode

    # REFERENCES - minimal VBA + stdole refs
    # Reference to {000204EF-0000-0000-C000-000000000046} stdole
    ref_name = b'stdole'
    buf.write(_tlv(0x0016, ref_name))  # REFERENCENAME
    libid = b'*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation'
    buf.write(_tlv(0x000D, struct.pack('<I', len(libid)) + libid))  # REFERENCEREGISTERED

    # PROJECTMODULES
    buf.write(_tlv(0x000F, struct.pack('<H', 1)))  # Module count
    buf.write(_tlv(0x0013, struct.pack('<H', 0xFFFF)))  # Cookie

    # MODULE record
    name_bytes = module_name.encode('ascii')
    buf.write(_tlv(0x0019, name_bytes))  # MODULENAME
    buf.write(_tlv(0x0047, module_name.encode('utf-16-le')))  # MODULENAMEUNICODE
    buf.write(_tlv(0x001C, code_name.encode('ascii')))  # MODULESTREAMNAME
    buf.write(_tlv(0x0032, code_name.encode('utf-16-le')))  # MODULESTREAMNAME unicode
    buf.write(_tlv(0x001E, b''))  # MODULEDOCSTRING
    buf.write(_tlv(0x0048, b''))  # MODULEDOCSTRING unicode
    buf.write(_tlv(0x0031, struct.pack('<I', 0)))  # MODULEOFFSET
    buf.write(_tlv(0x001A, struct.pack('<I', 0)))  # MODULEHELPCONTEXT
    buf.write(_tlv(0x002C, struct.pack('<I', 0)))  # MODULECOOKIE
    buf.write(_tlv(0x0021, struct.pack('<I', 0x00000022)))  # MODULETYPE (document module)
    buf.write(struct.pack('<HI', 0x002B, 0))  # MODULEEOF

    # dir stream terminator
    buf.write(struct.pack('<HI', 0x0010, 0))  # PROJECTEOF

    return buf.getvalue()


# ---------------------------------------------------------------------------
# C. vbaProject.bin builder (Compound Binary File / CFBF)
# ---------------------------------------------------------------------------

_SECT_SIZE = 512
_MINI_SECT_SIZE = 64
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_FATSECT = 0xFFFFFFFD


def _pad(data: bytes, boundary: int) -> bytes:
    """Pad data naar veelvoud van boundary."""
    remainder = len(data) % boundary
    if remainder:
        data += b'\x00' * (boundary - remainder)
    return data


def _build_cfbf(streams: dict) -> bytes:
    """Bouw een minimaal maar valide CFBF (OLE) bestand.

    streams is een dict met volledige pad-namen als keys en bytes als values.
    We ondersteunen een platte structuur: Root Entry -> VBA storage -> streams.
    """
    # Bereken sector allocatie
    # Streams die we opslaan (in deze volgorde na de header):
    # 1. FAT sector (1 sector)
    # 2. Stream data sectors
    #
    # Directory entries:
    # 0: Root Entry (storage)
    # 1: VBA (storage)
    # 2+: individuele streams

    # Sorteer streams en wijs directory entry indices toe
    stream_names = list(streams.keys())
    dir_entries = []

    # Root Entry
    dir_entries.append({
        'name': 'Root Entry',
        'type': 5,  # Root storage
        'child': 1,
    })
    # VBA storage
    dir_entries.append({
        'name': 'VBA',
        'type': 1,  # Storage
        'child': -1,
    })

    # Stream entries onder VBA
    vba_streams = []
    top_streams = []
    for name in stream_names:
        if name.startswith('VBA/'):
            vba_streams.append(name)
        else:
            top_streams.append(name)

    # Voeg VBA child streams toe
    for name in vba_streams:
        short_name = name.split('/', 1)[1]
        dir_entries.append({
            'name': short_name,
            'type': 2,  # Stream
            'data': streams[name],
        })

    # Voeg top-level streams toe (PROJECT, PROJECTwm)
    for name in top_streams:
        dir_entries.append({
            'name': name,
            'type': 2,
            'data': streams[name],
        })

    # Stel sibling links in (rode-zwarte boom, simpele lineaire keten)
    # VBA storage children
    vba_child_indices = list(range(2, 2 + len(vba_streams)))
    top_child_indices = list(range(2 + len(vba_streams), len(dir_entries)))

    # Simpele binaire boom opbouw: middelste als root, links/rechts recursief
    def _build_tree(indices):
        if not indices:
            return -1
        mid = len(indices) // 2
        entry = dir_entries[indices[mid]]
        entry['left'] = _build_tree(indices[:mid])
        entry['right'] = _build_tree(indices[mid + 1:])
        return indices[mid]

    if vba_child_indices:
        dir_entries[1]['child'] = _build_tree(vba_child_indices)

    # Top-level children: VBA + PROJECT streams
    all_root_children = [1] + top_child_indices
    dir_entries[0]['child'] = _build_tree(all_root_children)

    # Wijs sectoren toe aan stream data
    sector_data = []  # lijst van 512-byte sectors
    fat_entries = []  # FAT entries (1 per sector)

    # Reserveer sector 0 voor de FAT zelf
    sector_data.append(None)  # placeholder, vullen we later
    fat_entries.append(_FATSECT)  # FAT sector marker

    # Wijs stream data toe aan sectoren
    for entry in dir_entries:
        if entry['type'] == 2 and entry.get('data'):
            data = entry['data']
            padded = _pad(data, _SECT_SIZE)
            n_sectors = len(padded) // _SECT_SIZE
            start_sect = len(sector_data)
            entry['start_sect'] = start_sect
            entry['size'] = len(data)
            for i in range(n_sectors):
                sect = padded[i * _SECT_SIZE:(i + 1) * _SECT_SIZE]
                sector_data.append(sect)
                if i < n_sectors - 1:
                    fat_entries.append(start_sect + i + 1)
                else:
                    fat_entries.append(_ENDOFCHAIN)
        elif entry['type'] == 2:
            entry['start_sect'] = _ENDOFCHAIN
            entry['size'] = 0

    # Directory sectors
    dir_data = bytearray()
    for entry in dir_entries:
        dir_data.extend(_build_dir_entry(entry))
    # Pad directory naar veelvoud van 512
    dir_data = _pad(bytes(dir_data), _SECT_SIZE)

    dir_start = len(sector_data)
    n_dir_sects = len(dir_data) // _SECT_SIZE
    for i in range(n_dir_sects):
        sector_data.append(dir_data[i * _SECT_SIZE:(i + 1) * _SECT_SIZE])
        if i < n_dir_sects - 1:
            fat_entries.append(dir_start + i + 1)
        else:
            fat_entries.append(_ENDOFCHAIN)

    # Root Entry grootte instellen (voor mini-stream container, hier 0)
    dir_entries[0]['size'] = 0
    dir_entries[0]['start_sect'] = _ENDOFCHAIN

    # Bouw FAT sector
    # Pad FAT entries tot 128 (512/4)
    while len(fat_entries) < 128:
        fat_entries.append(_FREESECT)
    fat_sector = b''.join(struct.pack('<I', e) for e in fat_entries[:128])
    sector_data[0] = fat_sector

    # Bouw header (512 bytes)
    header = _build_cfbf_header(
        fat_sectors=[0],
        dir_start=dir_start,
        total_sectors=len(sector_data),
    )

    # Assembleer het bestand
    out = io.BytesIO()
    out.write(header)
    for sect in sector_data:
        if sect is None:
            out.write(b'\x00' * _SECT_SIZE)
        else:
            out.write(sect)
    return out.getvalue()


def _build_cfbf_header(fat_sectors, dir_start, total_sectors):
    """Bouw de 512-byte CFBF header."""
    header = bytearray(512)

    # Magic number
    header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    # Minor version
    struct.pack_into('<H', header, 0x18, 0x003E)
    # Major version (3 = v3)
    struct.pack_into('<H', header, 0x1A, 0x0003)
    # Byte order (little endian)
    struct.pack_into('<H', header, 0x1C, 0xFFFE)
    # Sector size power (9 = 512)
    struct.pack_into('<H', header, 0x1E, 0x0009)
    # Mini sector size power (6 = 64)
    struct.pack_into('<H', header, 0x20, 0x0006)
    # Total sectors in dir
    struct.pack_into('<I', header, 0x28, 0)
    # Total FAT sectors
    struct.pack_into('<I', header, 0x2C, len(fat_sectors))
    # First directory sector
    struct.pack_into('<I', header, 0x30, dir_start)
    # Transaction signature
    struct.pack_into('<I', header, 0x34, 0)
    # Mini stream cutoff size
    struct.pack_into('<I', header, 0x38, 0x00001000)
    # First mini FAT sector
    struct.pack_into('<I', header, 0x3C, _ENDOFCHAIN)
    # Total mini FAT sectors
    struct.pack_into('<I', header, 0x40, 0)
    # First DIFAT sector
    struct.pack_into('<I', header, 0x44, _ENDOFCHAIN)
    # Total DIFAT sectors
    struct.pack_into('<I', header, 0x48, 0)

    # DIFAT array (109 entries, starting at offset 0x4C)
    for i in range(109):
        if i < len(fat_sectors):
            struct.pack_into('<I', header, 0x4C + i * 4, fat_sectors[i])
        else:
            struct.pack_into('<I', header, 0x4C + i * 4, _FREESECT)

    return bytes(header)


def _build_dir_entry(entry):
    """Bouw een 128-byte directory entry."""
    raw = bytearray(128)

    name = entry['name']
    # UTF-16LE naam (max 32 chars inclusief null)
    name_utf16 = name.encode('utf-16-le') + b'\x00\x00'
    name_len = min(len(name_utf16), 64)
    raw[0:name_len] = name_utf16[:name_len]
    # Name size in bytes (inclusief null terminator)
    struct.pack_into('<H', raw, 0x40, name_len)

    # Object type
    raw[0x42] = entry['type']

    # Color (1 = black)
    raw[0x43] = 1

    # Left/right/child
    left = entry.get('left', -1)
    right = entry.get('right', -1)
    child = entry.get('child', -1)
    struct.pack_into('<i', raw, 0x44, left if left != -1 else -1)
    struct.pack_into('<i', raw, 0x48, right if right != -1 else -1)
    struct.pack_into('<i', raw, 0x4C, child if child != -1 else -1)

    # CLSID (16 nullen)
    # Creation time, modification time (8+8 nullen)

    # Start sector
    start = entry.get('start_sect', _ENDOFCHAIN)
    if start == -1:
        start = _ENDOFCHAIN
    struct.pack_into('<I', raw, 0x74, start)

    # Size
    struct.pack_into('<I', raw, 0x78, entry.get('size', 0))

    return bytes(raw)


def build_vba_project_bin(module_name: str, vba_source: str) -> bytes:
    """Bouw een compleet vbaProject.bin bestand.

    Args:
        module_name: De module naam ('ThisDocument' voor Word, 'ThisWorkbook' voor Excel)
        vba_source: De VBA broncode
    """
    # Module stream: Attribute header + compressed source
    attrs = (
        f'Attribute VB_Name = "{module_name}"\r\n'
        f'Attribute VB_Base = "0{{FCFB3D2A-A0FA-1068-A738-08002B3371B5}}"\r\n'
        f'Attribute VB_GlobalNameSpace = False\r\n'
        f'Attribute VB_Creatable = False\r\n'
        f'Attribute VB_PredeclaredId = True\r\n'
        f'Attribute VB_Exposed = True\r\n'
        f'Attribute VB_TemplateDerived = False\r\n'
        f'Attribute VB_Customizable = True\r\n'
    )
    full_source = attrs + vba_source
    compressed_source = _ovba_compress(full_source.encode('ascii'))

    # Bereken offset naar source code (na attributes)
    # Het offset in de dir stream wijst naar waar de gecomprimeerde data begint
    # In ons geval is het hele stream gecomprimeerd, offset = 0

    # _VBA_PROJECT stream (minimaal 7 bytes)
    vba_project_stream = struct.pack('<HBH', 0x61CC, 0x00, 0x0000) + b'\x00\x00'

    # dir stream (gecomprimeerd)
    dir_raw = _build_dir_stream(module_name, module_name)
    dir_compressed = _ovba_compress(dir_raw)

    # PROJECT stream (tekst)
    project_text = (
        f'ID="{{00000000-0000-0000-0000-000000000000}}"\r\n'
        f'Document={module_name}/&H00000000\r\n'
        f'Name="VBAProject"\r\n'
        f'HelpContextID="0"\r\n'
        f'VersionCompatible32="393222000"\r\n'
        f'CMG="0000"\r\n'
        f'DPB="0000"\r\n'
        f'GC="0000"\r\n'
        f'\r\n'
        f'[Host Extender Info]\r\n'
        f'&H00000001={{3832D640-CF90-11CF-8E43-00A0C911005A}};VBE;&H00000000\r\n'
    )
    project_stream = project_text.encode('ascii')

    # PROJECTwm stream (unicode name mapping)
    projectwm = module_name.encode('ascii') + b'\x00' + module_name.encode('utf-16-le') + b'\x00\x00' + b'\x00'

    # Assembleer alle streams
    streams = {
        'VBA/_VBA_PROJECT': vba_project_stream,
        'VBA/dir': dir_compressed,
        f'VBA/{module_name}': compressed_source,
        'PROJECT': project_stream,
        'PROJECTwm': projectwm,
    }

    return _build_cfbf(streams)


# ---------------------------------------------------------------------------
# D. inject_macro() — ZIP manipulatie
# ---------------------------------------------------------------------------

_WORD_MAIN_CT = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
_WORD_MACRO_CT = 'application/vnd.ms-word.document.macroEnabled.main+xml'
_EXCEL_MAIN_CT = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'
_EXCEL_MACRO_CT = 'application/vnd.ms-excel.sheet.macroEnabled.main+xml'

_VBA_PROJECT_CT = 'application/vnd.ms-office.vbaProject'

_WORD_TRIGGERS = '\nSub Document_Open()\n    Meth\nEnd Sub\n\nSub AutoOpen()\n    Meth\nEnd Sub\n'
_EXCEL_TRIGGERS = '\nSub Workbook_Open()\n    Meth\nEnd Sub\n\nSub Auto_Open()\n    Meth\nEnd Sub\n'


def detect_doc_type(path: str) -> str:
    """Detecteer document type op basis van extensie.

    Returns: 'word' of 'excel'
    Raises: ValueError als extensie niet ondersteund is
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.docx', '.docm'):
        return 'word'
    elif ext in ('.xlsx', '.xlsm'):
        return 'excel'
    raise ValueError(f"Niet-ondersteunde extensie: {ext}")


def _default_output_path(input_path: str, doc_type: str) -> str:
    """Genereer standaard output pad (.docx->.docm, .xlsx->.xlsm)."""
    base = os.path.splitext(input_path)[0]
    if doc_type == 'word':
        return base + '.docm'
    return base + '.xlsm'


def _get_triggers(doc_type: str) -> str:
    """Haal de juiste trigger subs op voor het document type."""
    if doc_type == 'word':
        return _WORD_TRIGGERS
    return _EXCEL_TRIGGERS


def _get_module_name(doc_type: str) -> str:
    """Haal de juiste module naam op voor het document type."""
    if doc_type == 'word':
        return 'ThisDocument'
    return 'ThisWorkbook'


def _update_content_types(xml_content: str, doc_type: str) -> str:
    """Update [Content_Types].xml met vbaProject en macro content types."""
    import xml.etree.ElementTree as ET

    ns = 'http://schemas.openxmlformats.org/package/2006/content-types'
    ET.register_namespace('', ns)
    root = ET.fromstring(xml_content)

    # Voeg vbaProject override toe
    vba_part = '/word/vbaProject.bin' if doc_type == 'word' else '/xl/vbaProject.bin'
    override = ET.SubElement(root, f'{{{ns}}}Override')
    override.set('PartName', vba_part)
    override.set('ContentType', _VBA_PROJECT_CT)

    # Wijzig main content type naar macroEnabled variant
    old_ct = _WORD_MAIN_CT if doc_type == 'word' else _EXCEL_MAIN_CT
    new_ct = _WORD_MACRO_CT if doc_type == 'word' else _EXCEL_MACRO_CT

    for elem in root.iter(f'{{{ns}}}Override'):
        if elem.get('ContentType') == old_ct:
            elem.set('ContentType', new_ct)

    return ET.tostring(root, encoding='unicode', xml_declaration=True)


def _update_relationships(xml_content: str, doc_type: str) -> str:
    """Voeg vbaProject relatie toe aan het relationships bestand."""
    import xml.etree.ElementTree as ET

    ns = 'http://schemas.openxmlformats.org/package/2006/relationships'
    ET.register_namespace('', ns)
    root = ET.fromstring(xml_content)

    # Zoek het hoogste rId nummer
    max_id = 0
    for rel in root.iter(f'{{{ns}}}Relationship'):
        rid = rel.get('Id', '')
        if rid.startswith('rId'):
            try:
                num = int(rid[3:])
                max_id = max(max_id, num)
            except ValueError:
                pass

    new_id = f'rId{max_id + 1}'
    rel = ET.SubElement(root, f'{{{ns}}}Relationship')
    rel.set('Id', new_id)
    rel.set('Type', 'http://schemas.microsoft.com/office/2006/relationships/vbaProject')
    rel.set('Target', 'vbaProject.bin')

    return ET.tostring(root, encoding='unicode', xml_declaration=True)


def inject_macro(input_path: str, vba_source: str, output_path: str = None) -> str:
    """Injecteer VBA macro in een Office document.

    Args:
        input_path: Pad naar het bron .docx of .xlsx bestand
        vba_source: VBA broncode (zonder triggers, die worden automatisch toegevoegd)
        output_path: Optioneel output pad. Standaard: .docm/.xlsm variant

    Returns:
        Het pad naar het output bestand
    """
    doc_type = detect_doc_type(input_path)
    if output_path is None:
        output_path = _default_output_path(input_path, doc_type)

    module_name = _get_module_name(doc_type)
    vba_bin = build_vba_project_bin(module_name, vba_source)

    # Bepaal paden
    vba_part = 'word/vbaProject.bin' if doc_type == 'word' else 'xl/vbaProject.bin'
    rels_path = 'word/_rels/document.xml.rels' if doc_type == 'word' else 'xl/_rels/workbook.xml.rels'

    with zipfile.ZipFile(input_path, 'r') as zin:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)

                if item.filename == '[Content_Types].xml':
                    data = _update_content_types(
                        data.decode('utf-8'), doc_type
                    ).encode('utf-8')
                elif item.filename == rels_path:
                    data = _update_relationships(
                        data.decode('utf-8'), doc_type
                    ).encode('utf-8')

                zout.writestr(item, data)

            # Voeg vbaProject.bin toe
            zout.writestr(vba_part, vba_bin)

    return output_path
