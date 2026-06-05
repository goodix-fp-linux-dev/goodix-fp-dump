"""Driver for the Goodix GF3206 ("MilanG") sensor, USB 27c6:5f10.

Found e.g. in the power button of the Honor MagicBook X16 Pro. The sensor
speaks standard TLS-PSK over USB and streams a 56x176 raw frame; the useful
54 pixels per scan row are 12-bit packed and the decoded rows are transposed
into a 176x54 image.

Unlike the 51x0 the PSK provisioning uses a white-box blob (see wb_pure.py).
This driver never flashes firmware; it only provisions the all-zero PSK if
needed, then captures a clear frame and a fingerprint frame.

The descramble was derived from gfusb.dll (MilanGDataRegroup) and matches the
tlambertz/goodix-fingerprint-reversing project bit for bit.
"""
import hashlib
import hmac
import random
import socket
import subprocess
import time

import goodix
import protocol
import tool
import wb_pure

TARGET_FIRMWARE_PREFIX = "GF_ST411SEC_APP_"

# All-zero raw PSK. The device stores the derived PMK below after provisioning.
PSK = bytes(32)
PMK_HASH = bytes.fromhex(
    "b5e0beeb94c84eb99b883abd5c251073c56b91035c562a91a46c7f3349c36c89")

# TLS-PSK cipher the device offers (PSK-AES128-GCM-SHA256). SECLEVEL=0 lets
# recent OpenSSL negotiate this otherwise-disabled suite.
CIPHER = "PSK-AES128-GCM-SHA256@SECLEVEL=0"

# MCU config captured from the Windows driver (matches the wire bit for bit).
CONFIG = bytes.fromhex(
    "3011647500752ca11cbd18d500d500d500ba000080ca0006008400beb28600c5b9"
    "8800b5ad8a009d958c0000be8e0000c5900000b59200009d940000af960000bf98"
    "0000b69a0000a7d2000000d4000000d6000000d800000012000304d00000007000"
    "0000720078567400341220001040200208102a0182032200012024001400800001"
    "045c00000156000c245800050032000802660000027c000038820080152a010800"
    "5c008000540000016200380464001000660000027c0001382a0108005c00800052"
    "00080054000001660000027c0001380000000000000000000000")

# FDT thresholds. fdt-down uses higher per-cell values than fdt-mode so the
# device only reports finger-down on real contact (the command then blocks).
FDT_MODE = bytes.fromhex("0d0180a08093809b80948090808f8094808b808a8083")
FDT_DOWN = bytes.fromhex("0c0180b980b480b580af80b480ac80b280a780ab80a5")

# Geometry (GF3206).
WIRE_BODY = 14784   # 176 rows * 84 bytes
ROW_STRIDE = 84     # bytes per wire row
ROW_USE = 82        # useful bytes per row ((54 * 3) / 2 + 1)
NROWS = 176         # wire rows (= width after transpose)
NCOLS = 54          # pixels per row (= height after transpose)


def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)

    device.nop()
    device.enable_chip(True)
    device.nop()

    return device


def check_psk(device: goodix.Device):
    success, flags, psk = device.preset_psk_read(0xbb020003)
    if not success:
        raise ValueError("Failed to read PSK")

    if flags != 0xbb020003:
        raise ValueError("Invalid flags")

    print(f"PSK: {psk.hex()}")
    return psk == PMK_HASH


def write_psk(device: goodix.Device):
    # Provision the all-zero PSK via its white-box blob (see wb_pure.py).
    if not device.preset_psk_write(0xbb010003, wb_pure.encode(PSK)):
        return False

    return check_psk(device)


# --- TLS 1.2 PRF (used to derive the session keys for manual decryption) ---
def _p_hash(secret, seed, n):
    out = b""
    a = seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:n]


def _prf(secret, label, seed, n):
    return _p_hash(secret, label + seed, n)


def handshake(device: goodix.Device, tls_client: socket.socket):
    # Proxy the device's TLS handshake through the local OpenSSL server, then
    # derive the client write key/iv so we can decrypt the image records
    # ourselves (the server's stdout is not used for the payload).
    client_hello = device.request_tls_connection()
    tls_client.sendall(client_hello)

    server_hello = tls_client.recv(4096)
    device.protocol.write(
        goodix.encode_message_pack(server_hello,
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    for _ in range(3):
        tls_client.sendall(
            goodix.check_message_pack(
                device.protocol.read(),
                goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    finished = tls_client.recv(4096)
    device.protocol.write(
        goodix.encode_message_pack(finished,
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))
    time.sleep(0.01)

    client_random, server_random = client_hello[11:43], server_hello[11:43]
    premaster = b"\x00\x20" + bytes(32) + b"\x00\x20" + PSK
    master = _prf(premaster, b"master secret",
                  client_random + server_random, 48)
    key_block = _prf(master, b"key expansion",
                     server_random + client_random, 40)
    client_key, client_iv = key_block[0:16], key_block[32:36]

    device.tls_successfully_established()
    return client_key, client_iv


def decrypt_image(client_key, client_iv, enc, seq):
    # The device sends each image as one TLS application-data record. The
    # record sequence number increases per record, so try a small window.
    from Crypto.Cipher import AES

    body = enc[5:]
    explicit, ct_tag = body[:8], body[8:]
    nonce = client_iv + explicit
    pt_len = len(ct_tag) - 16
    ct, tag = ct_tag[:pt_len], ct_tag[pt_len:]

    for candidate in [seq] + [seq + i for i in range(-2, 10)]:
        if candidate < 0:
            continue
        aad = (candidate.to_bytes(8, "big") + b"\x17\x03\x03" +
               pt_len.to_bytes(2, "big"))
        try:
            cipher = AES.new(client_key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            pt = cipher.decrypt_and_verify(ct, tag)
            return candidate + 1, pt
        except (ValueError, KeyError):
            continue
    return seq, None


def descramble(plaintext):
    # wire body (sparse 12-bit packing) -> 54x176 grayscale (list of ints).
    body = plaintext[8:8 + WIRE_BODY]
    packed = bytearray()
    for r in range(NROWS):
        packed += body[r * ROW_STRIDE:r * ROW_STRIDE + ROW_USE]

    rows = []
    for r in range(NROWS):
        b = packed[r * ROW_USE:(r + 1) * ROW_USE]
        out = []
        i = 0
        col = 0
        while col < NCOLS:
            if col == NCOLS - 2:  # last group: 4 bytes -> 2 pixels
                out.append((b[i] & 0xf) * 0x100 + b[i + 1])
                out.append(b[i + 3] * 0x10 + (b[i] >> 4))
                col += 2
                i += 4
            else:                 # 6 bytes -> 4 pixels
                out.append((b[i] & 0xf) * 0x100 + b[i + 1])
                out.append(b[i + 3] * 0x10 + (b[i] >> 4))
                out.append((b[i + 5] & 0xf) * 0x100 + b[i + 2])
                out.append(b[i + 4] * 0x10 + (b[i + 5] >> 4))
                col += 4
                i += 6
        rows.append(out[:NCOLS])

    # transpose to a 176-wide x 54-tall image, row-major, raw 12-bit values
    flat = []
    for c in range(NCOLS):
        for r in range(NROWS):
            flat.append(rows[r][c])
    return flat


def run_driver(device: goodix.Device):
    tls_server = subprocess.Popen([
        "openssl", "s_server", "-nocert", "-psk", PSK.hex(), "-port", "4433",
        "-quiet", "-tls1_2", "-cipher", CIPHER
    ],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    try:
        device.reset(True, False, 20)
        device.read_sensor_register(0x0000, 4)
        device.nop()
        device.read_otp()

        # The GF3206 acknowledges the config upload with a 0x00 status byte,
        # which the generic helper reports as failure, so ignore the result.
        device.upload_config_mcu(CONFIG)

        device.set_powerdown_scan_frequency(100)

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))
        try:
            client_key, client_iv = handshake(device, tls_client)
            seq = 1

            # Clear (baseline) frame, no finger.
            device.mcu_switch_to_fdt_mode(FDT_MODE, True)
            device.mcu_switch_to_fdt_down(FDT_DOWN, False)
            enc = device.mcu_get_image(
                b"\x01\x00", goodix.FLAGS_TRANSPORT_LAYER_SECURITY)
            seq, plaintext = decrypt_image(client_key, client_iv, enc, seq)
            if plaintext:
                tool.write_pgm(descramble(plaintext), NCOLS, NROWS,
                               "clear.pgm")

            # Fingerprint frame: fdt-down blocks until the finger touches.
            print("Waiting for finger...")
            device.mcu_switch_to_fdt_mode(FDT_MODE, True)
            device.mcu_switch_to_fdt_down(FDT_DOWN, True)
            enc = device.mcu_get_image(
                b"\x01\x00", goodix.FLAGS_TRANSPORT_LAYER_SECURITY)
            seq, plaintext = decrypt_image(client_key, client_iv, enc, seq)
            if plaintext:
                tool.write_pgm(descramble(plaintext), NCOLS, NROWS,
                               "fingerprint.pgm")
                print("Saved fingerprint.pgm")
        finally:
            tls_client.close()
    finally:
        tls_server.terminate()


def main(product: int):
    print(
        tool.warning(
            "This program might break your device.\n"
            "Continue at your own risk.\n"
            "But don't hold us responsible if your device is broken!\n"
            "Don't run this program as part of a regular process."))

    code = random.randint(0, 9999)
    if input(f"Type {code} to continue and confirm that you are not a bot: "
             ) != str(code):
        print("Abort")
        return

    device = init_device(product)

    firmware = device.firmware_version()
    print(f"Firmware: {firmware}")
    if not firmware.startswith(TARGET_FIRMWARE_PREFIX):
        raise ValueError(f"Invalid firmware: {firmware}")

    if not check_psk(device):
        print("Provisioning all-zero PSK...")
        if not write_psk(device):
            raise ValueError("Failed to write PSK")

    run_driver(device)
