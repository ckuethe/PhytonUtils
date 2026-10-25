"""Tests for the Python port of PhytonUtils.

Verifies behavior against the known-good values from the Go library's tests.
"""

import os
import re
import struct
import sys
import unittest

# Allow running directly from the repo root.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from phytonutils import crc  # noqa: E402
from phytonutils.compression import compress, decompress  # noqa: E402
from phytonutils.encryption import (  # noqa: E402
    block as blk,
    deviceid,
    generator as gen,
    material as mat,
    bruteforce,
)
from phytonutils.firmware import firmware as ff  # noqa: E402
from phytonutils.firmware import flash  # noqa: E402
from phytonutils.encryption import borlandrand as br  # noqa: E402


def parse_go_array(text, name):
    """Extracts a Go byte array literal from source text."""
    m = re.search(r"var " + name + r"\s*=\s*[A-Za-z\[\]\.]*\{", text, re.S)
    if not m:
        raise ValueError("not found " + name)
    start = m.end()
    depth = 1
    body = None
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                body = text[start:i]
                break
    return bytes(int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+", body))


def _load_go_file(name):
    with open(os.path.join(_ROOT, "encryption", name)) as f:
        return f.read()


class CrcTest(unittest.TestCase):
    def test_initial_value(self):
        self.assertEqual(crc.calculate_crc(b""), 0xFFFFFFFF)

    def test_known_values_from_deviceid(self):
        # CRC values asserted by the Go deviceid tests after decryption
        did = deviceid.DeviceId([0x003B0056, 0x4D4B5002, 0x20323455])
        text = _load_go_file("deviceid_test.go")
        for var, expected in (("sampleEncryptedCodeA", 0x39F8C16E), ("sampleEncryptedCodeB", 0x475F4CC9)):
            code = bytearray(parse_go_array(text, var))
            deviceid.decrypt_device_code(did, code)
            self.assertEqual(crc.calculate_crc(code), expected)


class DeviceIdTest(unittest.TestCase):
    def test_decrypt_roundtrip(self):
        did = deviceid.DeviceId([0x003B0056, 0x4D4B5002, 0x20323455])
        text = _load_go_file("deviceid_test.go")
        original = parse_go_array(text, "sampleEncryptedCodeA")
        code = bytearray(original)
        deviceid.decrypt_device_code(did, code)
        deviceid.encrypt_device_code(did, code)
        self.assertEqual(bytes(code), original)


class CompressionTest(unittest.TestCase):
    def test_roundtrip(self):
        for seed in range(5):
            data = os.urandom(3000)
            for exhaustive in (False, True):
                packed = compress.firmware_block_compress(data, exhaustive)
                unpacked = decompress.firmware_block_decompress(packed)
                self.assertEqual(unpacked, data)

    def test_sample_firmware_compressed(self):
        # Decompressing the data from the Go firmware-compressed sample must
        # match the CRC stored in the block.
        text = _load_go_file("block_testdata.go")
        fwc = parse_go_array(text, "sampleBlockFirmwareCompressed")
        eb = blk.EncryptedBlock(fwc)
        eb.decrypt(mat.new_flash_key_material(None), False)
        raw_comp = bytes(eb.data_block()[: len(fwc) - blk.ENCRYPTED_BLOCK_KEY_SIZE - 3])
        unpacked = decompress.firmware_block_decompress(raw_comp)
        crc1, _ = eb.crc()
        self.assertEqual(crc.calculate_crc(unpacked), crc1)

        # Recompressing must roundtrip to the same CRC
        for exhaustive in (False, True):
            packed = compress.firmware_block_compress(unpacked, exhaustive)
            self.assertEqual(
                crc.calculate_crc(decompress.firmware_block_decompress(packed)), crc1
            )


class EncryptedBlockTest(unittest.TestCase):
    def _sample(self, name):
        return parse_go_array(_load_go_file("block_testdata.go"), name)

    def test_decrypt_memory_empty(self):
        eb = blk.EncryptedBlock(self._sample("sampleBlockMemoryEmpty"))
        eb.decrypt(mat.new_memory_key_material(None), True)

    def test_decrypt_memory_empty_broken_crc(self):
        eb = blk.EncryptedBlock(self._sample("sampleBlockMemoryEmptyBrokenCRC"))
        material = mat.new_memory_key_material(None)
        material.crc = lambda data: crc.calculate_crc(data) & 0xFFFF
        eb.decrypt(material, True)

    def test_encrypt_decrypt_roundtrip(self):
        eb = blk.new_encrypted_block(64)
        for i in range(len(eb.data_block())):
            eb[i + blk.ENCRYPTED_BLOCK_KEY_SIZE] = os.urandom(1)[0]
        original = bytes(eb.data_block())
        material = mat.new_memory_key_material(gen.SecureRandomKeyGenerator())
        eb.encrypt(material)
        dec = blk.EncryptedBlock(eb.bytes())
        dec.decrypt(material, True)
        self.assertEqual(bytes(dec.data_block()), original)

    def test_encrypt_decrypt_borland(self):
        eb = blk.new_encrypted_block(64)
        for i in range(len(eb.data_block())):
            eb[i + blk.ENCRYPTED_BLOCK_KEY_SIZE] = os.urandom(1)[0]
        original = bytes(eb.data_block())
        material = mat.new_flash_key_material(gen.BorlandRandKeyGenerator(0x12345678))
        eb.encrypt(material)
        dec = blk.EncryptedBlock(eb.bytes())
        dec.decrypt(material, True)
        self.assertEqual(bytes(dec.data_block()), original)


class BruteforceTest(unittest.TestCase):
    def test_finds_original_seed(self):
        eb = blk.new_encrypted_block(64)
        for i in range(len(eb.data_block())):
            eb[i + blk.ENCRYPTED_BLOCK_KEY_SIZE] = os.urandom(1)[0]
        original_seed = 0x12345678
        material = mat.new_flash_key_material(gen.BorlandRandKeyGenerator(original_seed))
        eb.encrypt(material)
        seeds = bruteforce.bruteforce_borland_seed(eb, mat.new_flash_key_material(None))
        self.assertIn(original_seed, seeds)


class BorlandRandTest(unittest.TestCase):
    def test_next_previous_seed(self):
        self.assertEqual(br.borland_rand_next_seed(br.borland_rand_previous_seed(0xDEADBEEF)), 0xDEADBEEF)

    def test_xor_uint32_roundtrip(self):
        seed = 0x00000000
        v, _ = br.borland_rand_xor_uint32(0x12345678, seed)
        # XORing with the same seed cancels out
        v2, _ = br.borland_rand_xor_uint32(v, seed)
        self.assertEqual(v2, 0x12345678)


class FlashTest(unittest.TestCase):
    def test_decode(self):
        seed = 0x12345678
        payload = struct.pack("<II", flash.FLASH_AREA_PUBLIC_SIGNATURE, 8 + 12) + bytes(12)
        size = len(payload)
        size_enc, s2 = br.borland_rand_xor_uint32(size, seed)
        br.borland_rand_xor_in_place(payload, s2)
        msg = struct.pack("<III", flash.FlashStatus.OK, seed, size_enc) + bytes(payload)
        area = flash.decode_read_flash_area(msg)
        self.assertEqual(area.public_signature, flash.FLASH_AREA_PUBLIC_SIGNATURE)
        self.assertEqual(area.struct_len, 20)


class FirmwareTest(unittest.TestCase):
    def test_load_and_extract(self):
        from phytonutils.firmware import keys as fkeys

        data = bytes([(i * 37) & 0xFF for i in range(100)])
        size_aligned = (len(data) + 7) & ~7
        eb = blk.new_encrypted_block(size_aligned)
        for i, b in enumerate(data):
            eb[i + blk.ENCRYPTED_BLOCK_KEY_SIZE] = b
        m = mat.new_flash_key_material(gen.BorlandRandKeyGenerator(0xDEADBEEF))
        eb.encrypt(m)
        block_bytes = struct.pack(
            "<III",
            12,
            len(data) ^ fkeys.BLOCK_HEADER_SIZE_KEY,
            (0x8000000 + 0x100) ^ fkeys.BLOCK_HEADER_ADDR_KEY,
        )
        block_bytes += bytes(eb.bytes())

        header_mid = struct.pack("<II", 0x1234, 1024) + bytes(16)
        header_mid += struct.pack("<BBIIBB", 1, 0, 1, 0, 0, 0) + struct.pack("<I", 0)
        header_size = 12 + len(header_mid)
        fw_bytes = b"Phyton\x00\x00" + struct.pack("<I", header_size) + header_mid + block_bytes

        fw = ff.load_firmware(fw_bytes)
        self.assertTrue(fw.file_header.marker == b"Phyton\x00\x00")
        code = fw.entries[0].code()
        self.assertEqual(bytes(code[0x100 : 0x100 + len(data)]), data)


class UtilsTest(unittest.TestCase):
    def test_hex_octets(self):
        from phytonutils import utils

        self.assertEqual(utils.hex_octets(bytes(range(8))), "0001020304050607")


if __name__ == "__main__":
    unittest.main()
