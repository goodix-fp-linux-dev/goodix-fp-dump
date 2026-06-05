"""Pure-Python white-box PSK encoder for Goodix fw127xx (e.g. GF3206 / 5f10).

The fw127xx firmware does not accept a raw PSK for COMMAND_PRESET_PSK_WRITE;
it expects a "white-box" blob from which it re-derives the PMK. This blob is
normally produced by an obfuscated routine in gfusb.dll (FUN_180006bd0). The
KDF constants below were recovered by emulating that routine and verified bit
for bit against it for arbitrary PSKs, so no DLL is needed at runtime. The
only dependency is `cryptography` (AES-256-GCM) plus hashlib/hmac.

The device re-derives and stores PMK = SHA256(whole blob); preset_psk_read
then returns that PMK.

Blob layout (102 bytes, the TLV2 value for preset_psk_write 0xbb010003):
  [0x00:0x20] HMAC-SHA256(HMAC_KEY, 02ff || len || ct || tag)
  [0x20:0x22] 02 ff
  [0x22:0x26] psk_len (little-endian u32)
  [0x26:0x36] SHA256(02ff || len || psk[:len>>2] || (03 as u32)*16)[:16] (GCM IV)
  [0x36:0x56] AES-256-GCM ciphertext(psk)
  [0x56:0x66] GCM tag
"""
import hashlib
import hmac
import struct

from Crypto.Cipher import AES

# Constants from the obfuscated gfusb.dll KDF (deterministic, PSK-independent).
K_GCM = bytes.fromhex(
    "58f013eeb7e216e2c1cd0e8fffa7dbd6799cd92aa149013ea0e9f9fd7dc6d94e")
HMAC_KEY = bytes.fromhex(
    "799cd92aa149013ea0e9f9fd7dc6d94e3ef63a7598c2a4933129e871ea03043b")
AAD = b"".join(
    struct.pack("<I", x)
    for x in (0xf0c12d52, 0x077d5699, 0xa3377ff4, 0x7d42842a))


def encode(psk: bytes) -> bytes:
    """Raw PSK (usually 32 bytes) -> 102-byte white-box blob for the device."""
    n = len(psk)
    hdr = b"\x02\xff" + struct.pack("<I", n)

    h = hashlib.sha256()
    h.update(hdr)
    h.update(psk[:n >> 2])  # the firmware hashes only psk[:len>>2]
    for _ in range(16):
        h.update(struct.pack("<I", 3))
    iv = h.digest()[:16]

    cipher = AES.new(K_GCM, AES.MODE_GCM, nonce=iv)
    cipher.update(AAD)
    ct, tag = cipher.encrypt_and_digest(psk)  # ciphertext(n) + tag(16)
    ct_tag = ct + tag
    outer = hmac.new(HMAC_KEY, hdr + ct_tag, hashlib.sha256).digest()
    return outer + hdr + iv + ct_tag


if __name__ == "__main__":
    print("encode(zeros) =", encode(bytes(32)).hex())
