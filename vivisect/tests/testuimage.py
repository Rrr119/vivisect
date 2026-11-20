import gzip
import logging
import os
import struct
import tempfile
import unittest

import vstruct.defs.uimage as v_uimage

import vivisect.cli as viv_cli
import vivisect.parsers as v_parsers

logger = logging.getLogger(__name__)


def crc32(data):
    # U-Boot uses the standard zlib/PNG CRC-32 (initial value 0).
    import zlib
    return zlib.crc32(data) & 0xffffffff


def buildUImage(payload, loadaddr, entry, arch, comp, name, timestamp=0):
    '''
    Build a legacy U-Boot uImage (with correct header/data CRCs) in memory.
    '''
    namebytes = name.encode('utf-8')[:v_uimage.IH_NMLEN]
    namebytes = namebytes.ljust(v_uimage.IH_NMLEN, b'\x00')

    hcrc_placeholder = 0
    header = struct.pack(
        '>IIIIIIIBBBB',
        v_uimage.IH_MAGIC,
        hcrc_placeholder,
        timestamp,
        len(payload),
        loadaddr,
        entry,
        crc32(payload),
        v_uimage.IH_OS_LINUX,
        arch,
        v_uimage.IH_TYPE_KERNEL,
        comp,
    ) + namebytes

    hcrc = crc32(header)
    header = struct.pack(
        '>IIIIIIIBBBB',
        v_uimage.IH_MAGIC,
        hcrc,
        timestamp,
        len(payload),
        loadaddr,
        entry,
        crc32(payload),
        v_uimage.IH_OS_LINUX,
        arch,
        v_uimage.IH_TYPE_KERNEL,
        comp,
    ) + namebytes

    return header + payload


class UImageTests(unittest.TestCase):
    # tiny ARM/Thumb-friendly payload: a couple of recognizable instructions
    # followed by a branch back to the start
    arm_payload = b'\x00\x00\xa0\xe3' + b'\x01\x00\xa0\xe3' + b'\x02\x00\xa0\xe3' + b'\xfd\xff\xff\xea'
    loadaddr = 0x80008000
    entry = 0x80008000

    def _loadWorkspace(self, image, arch=''):
        tmpd = tempfile.mkdtemp()
        fn = os.path.join(tmpd, 'firmware.uImage')
        with open(fn, 'wb') as f:
            f.write(image)

        vw = viv_cli.VivCli()
        if arch:
            vw.config.viv.parsers.uimage.arch = arch
        vw.loadFromFile(fn)
        return vw, fn

    def test_guessFormat(self):
        image = buildUImage(
            self.arm_payload, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_ARM, v_uimage.IH_COMP_NONE, 'test-firmware',
        )
        self.assertEqual(v_parsers.guessFormat(image[:32]), 'uimage')

        # non uImage bytes must not be misidentified
        self.assertEqual(v_parsers.guessFormat(b'\x7fELF' + b'\x00' * 28), 'elf')
        self.assertEqual(v_parsers.guessFormat(b':020000040000FA' + b'\x00' * 16), 'ihex')

    def test_parseUncompressed(self):
        image = buildUImage(
            self.arm_payload, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_ARM, v_uimage.IH_COMP_NONE, 'test-firmware',
        )
        vw, fn = self._loadWorkspace(image)

        self.assertEqual(vw.getMeta('Format'), 'uimage')
        self.assertEqual(vw.getMeta('Architecture'), 'arm')

        fname = vw.normFileName(fn)
        self.assertEqual(vw.getFileMeta(fname, 'uimage_name'), 'test-firmware')
        self.assertEqual(vw.getFileMeta(fname, 'uimage_loadaddr'), self.loadaddr)
        self.assertEqual(vw.getFileMeta(fname, 'uimage_entry'), self.entry)
        self.assertEqual(vw.getFileMeta(fname, 'uimage_comp'), v_uimage.IH_COMP_NONE)

        # segment map: header directly before payload at ih_load
        segments = vw.getSegments()
        seg_vas = sorted(va for va, size, name, sfname in segments)
        self.assertEqual(seg_vas, [
            self.loadaddr - v_uimage.IH_HDR_SIZE,
            self.loadaddr,
        ])

        hdrva = self.loadaddr - v_uimage.IH_HDR_SIZE
        self.assertEqual(vw.readMemory(hdrva, 4), struct.pack('>I', v_uimage.IH_MAGIC))
        self.assertEqual(vw.readMemory(self.loadaddr, len(self.arm_payload)), self.arm_payload)

        # entry point/export from ih_ep
        self.assertIn(self.entry, vw.getEntryPoints())
        exports = dict((va, name) for va, etype, name, sfname in vw.getExports())
        self.assertEqual(exports.get(self.entry), '__entry')

        # analysis compatibility: the loader must produce a function-capable map
        vw.makeFunction(self.entry)
        self.assertEqual(vw.getFunction(self.entry), self.entry)

    def test_parseGzip(self):
        compressed = gzip.compress(self.arm_payload)
        image = buildUImage(
            compressed, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_ARM, v_uimage.IH_COMP_GZIP, 'gzip-firmware',
        )
        vw, fn = self._loadWorkspace(image)

        fname = vw.normFileName(fn)
        self.assertEqual(vw.getFileMeta(fname, 'uimage_comp'), v_uimage.IH_COMP_GZIP)
        self.assertEqual(
            vw.getFileMeta(fname, 'uimage_uncompressed_size'), len(self.arm_payload),
        )
        # the mapped payload is the decompressed bytes, not the gzip stream
        self.assertEqual(vw.readMemory(self.loadaddr, len(self.arm_payload)), self.arm_payload)

    def test_archOverride(self):
        # ih_arch claims MIPS, which has no automatic mapping; force arm via config
        image = buildUImage(
            self.arm_payload, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_MIPS, v_uimage.IH_COMP_NONE, 'forced-arch',
        )
        vw, fn = self._loadWorkspace(image, arch='arm')
        self.assertEqual(vw.getMeta('Architecture'), 'arm')

    def test_missingArchRaises(self):
        image = buildUImage(
            self.arm_payload, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_MIPS, v_uimage.IH_COMP_NONE, 'no-arch',
        )
        with self.assertRaises(Exception):
            self._loadWorkspace(image)

    def test_baseaddrRelocation(self):
        image = buildUImage(
            self.arm_payload, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_ARM, v_uimage.IH_COMP_NONE, 'relocated',
        )
        tmpd = tempfile.mkdtemp()
        fn = os.path.join(tmpd, 'firmware.uImage')
        with open(fn, 'wb') as f:
            f.write(image)

        newbase = 0x00008000
        vw = viv_cli.VivCli()
        vw.loadFromFile(fn, baseaddr=newbase)

        seg_vas = sorted(va for va, size, name, sfname in vw.getSegments())
        self.assertEqual(seg_vas, [
            newbase - v_uimage.IH_HDR_SIZE,
            newbase,
        ])
        expected_entry = self.entry + (newbase - self.loadaddr)
        self.assertIn(expected_entry, vw.getEntryPoints())

    def test_corruptImage(self):
        import vivisect.exc as v_exc

        bad = b'XXXX' + b'\x00' * 128
        with self.assertRaises(v_exc.CorruptFile):
            v_parsers.getParserModule('uimage').parseBytes(viv_cli.VivCli(), bad)

        image = bytearray(buildUImage(
            self.arm_payload, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_ARM, v_uimage.IH_COMP_NONE, 'truncated',
        ))
        # claim a payload larger than what is actually present
        image[12:16] = struct.pack('>I', len(self.arm_payload) + 0x100)
        with self.assertRaises(v_exc.CorruptFile):
            v_parsers.getParserModule('uimage').parseBytes(viv_cli.VivCli(), bytes(image))

    def test_getMemBaseAndSize(self):
        image = buildUImage(
            self.arm_payload, self.loadaddr, self.entry,
            v_uimage.IH_ARCH_ARM, v_uimage.IH_COMP_NONE, 'sizing',
        )
        tmpd = tempfile.mkdtemp()
        fn = os.path.join(tmpd, 'firmware.uImage')
        with open(fn, 'wb') as f:
            f.write(image)

        mod = v_parsers.getParserModule('uimage')
        base, size = mod.getMemBaseAndSize(viv_cli.VivCli(), fn)
        self.assertEqual(base, self.loadaddr - v_uimage.IH_HDR_SIZE)
        self.assertEqual(size, v_uimage.IH_HDR_SIZE + len(self.arm_payload))
