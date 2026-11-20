"""Synthetic fixtures only. Never scans the user's files or executes samples."""
from pathlib import Path
import struct
import unittest
import yara

SOURCE = Path(__file__).resolve().parents[1] / 'detections/echo_integration/echo_rules.yar'
RULES = yara.compile(filepath=str(SOURCE))

def hits(data):
    return {m.rule for m in RULES.match(data=data)}

def dump(strings):
    header = bytearray(32)
    struct.pack_into('<II', header, 0, 0x504d444d, 0xa793)
    return bytes(header) + b'\0\0'.join(s.encode('utf-16le') for s in strings)

class RulesTests(unittest.TestCase):
    def test_graphics_dump(self):
        names = ['XINPUT1_4.dll','D3DCOMPILER_43.dll','dxgi.dll','DXCore.dll']
        self.assertEqual(hits(dump(names)), {'ECHO_DUMP_GRAPHICS_CONTEXT'})
        self.assertFalse(hits(dump(names[:-1])))
        self.assertFalse(hits(b'MZ' + dump(names)[4:]))

    def test_pymeow_dump(self):
        self.assertEqual(hits(dump(['d3d11.dll','xinput1_4.dll','pyMeow.pyd','dxcore.dll'])), {'ECHO_DUMP_PYMEOW_CONTEXT'})
        self.assertFalse(hits(dump(['d3d11.dll','xinput1_4.dll','dxcore.dll'])))

    def test_java_is_separate_from_driver(self):
        self.assertEqual(hits(b'import java.util.*; byte[] payload = url.openStream().readAllBytes();'), {'ECHO_JAVA_DOWNLOAD_CONTEXT'})
        self.assertFalse(hits(b'import java.util.*; class Hello {}'))
        self.assertFalse(hits(b'url.openStream().readAllBytes()'))

    def test_driver_requires_all_references(self):
        data=b'Nal Windows Driver Unload: Starting\0iqvw64e.pdb\0MmUnmapIoSpace'
        self.assertEqual(hits(data), {'ECHO_DRIVER_IQVW64E_REFERENCE'})
        self.assertFalse(hits(b'iqvw64e.pdb'))

    def test_generic_keys_and_gui_not_rules(self):
        self.assertFalse(hits(b'Input your key: imgui_impl_dx11 x64dbg.exe Discord FiveM'))

    def test_embedded_source_matches_reviewed_file(self):
        generated=SOURCE.with_name('yara_rules.h').read_text()
        self.assertIn(SOURCE.read_text(),generated)

if __name__ == '__main__':
    unittest.main()
