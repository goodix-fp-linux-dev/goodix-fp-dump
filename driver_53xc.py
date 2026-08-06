"""Driver for Goodix 27c6:533c -- GF5288 silicon on the wrapped protocol.

533c is the same GF5288 as the 53x5 family (chip 0x220ca1) but pairs it with a
GM168SEC secure element and speaks the wrapped framing from goodix.py rather
than the direct framing driver_53x5.py uses. So it is 53x5's device logic on
51x7's transport.

Unlike the other drivers here it never writes a PSK or touches firmware. 533c
ships with the all-zero PSK already provisioned, and read_firmware returns
nothing in APP mode -- there is no image to flash back, so mcu_erase_app would
be a one-way trip. If the PSK is not the expected one this driver refuses to
run rather than provisioning.

Sensor is 108x88, 12 bpp. Raw frames are dominated by fixed-pattern noise; a
reference frame captured with no finger is subtracted with a least-squares
scale and offset, which also absorbs the gain difference between captures.
"""
import hashlib
import hmac
import re
import socket
import statistics
import struct
import subprocess
import time

import usb.core

from Crypto.Cipher import AES

import goodix
import protocol
import tool

TARGET_FIRMWARE = "GF5288_GM168SEC_APP_13016"
VALID_FIRMWARE = r"GF5288_GM168SEC_APP_1[0-9]{4}"

PSK = bytes(32)
PSK_HASH = hashlib.sha256(PSK).digest()
PSK_FLAGS, PSK_LENGTH = 0xbb020001, 32

SENSOR_WIDTH, SENSOR_HEIGHT = 108, 88
IMAGE_BYTES = SENSOR_WIDTH * SENSOR_HEIGHT * 3 // 2

# captured from the vendor driver on an XPS 13 9310
DEVICE_CONFIG = bytes.fromhex(
    "40116c7d28a528cd1ce910f900f900f9"
    "000402000008001111ba000180ca0007"
    "008400beb28600c5b98800b5ad8a009d"
    "958c0000be8e0000c5900000b5920000"
    "9d940000af960000bf980000b69a0000"
    "a730006c1c50000105d0000000700000"
    "00720078567400341226000012200010"
    "4012000304020216212c020a032a0102"
    "002200012024003200800005045c0000"
    "01560028205800010032002402820080"
    "0c2002880d2a01920722000120240014"
    "00800005045c00940056000820580003"
    "0032000804820080112002280c2a0118"
    "045c0094005400000162000903640018"
    "008200800c2002280c2a0118045c0094"
    "00520008005400000100000000005113")

CAPTURE_REGISTER = 0x022c        # toggled around every capture
CAPTURE_ON, CAPTURE_OFF = b"\x0a\x03", b"\x0a\x02"

FDT_MODE_IDLE = b"\x0d\x01"      # measure baseline, do not arm
FDT_MODE_ARMED = b"\x8d\x01"
FDT_DOWN_ARMED = b"\x0c\x01"
FDT_UP_ARMED = b"\x0e\x01"


def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)

    device.nop()
    firmware = device.firmware_version()
    print(f"Firmware: {firmware}")

    if not re.fullmatch(VALID_FIRMWARE, firmware):
        raise ValueError(f"Unsupported firmware: {firmware}")

    success, _, psk_hash = device.preset_psk_read(PSK_FLAGS, PSK_LENGTH, 0)
    if not success or psk_hash != PSK_HASH:
        raise ValueError(
            "Sensor does not hold the all-zero PSK. This driver will not "
            "provision one: read_firmware returns nothing in APP mode, so a "
            "failed write could not be recovered from.")
    print("PSK: all-zero, as expected")

    return device


def fdt_template(baseline: bytes):
    """Build an FDT threshold template from a measured baseline.

    The baseline reply is a 4-byte header then 12-bit samples as 16-bit LE
    words. The vendor driver halves each sample and emits it twice, which is
    what the sensor expects back as the finger-detect threshold.
    """
    samples = [
        struct.unpack("<H", baseline[i:i + 2])[0]
        for i in range(4, len(baseline) - 1, 2)
    ]

    template = b""
    for sample in samples:
        template += struct.pack("<B", sample >> 1) * 2

    return template


def measure_baseline(device: goodix.Device, mode: bytes = FDT_MODE_IDLE):
    reply = device.mcu_switch_to_fdt_mode(mode + bytes(24), True)
    return fdt_template(reply)


def prf(secret: bytes, label: bytes, seed: bytes, length: int):
    """TLS 1.2 PRF with SHA-256."""
    out, a = b"", label + seed
    while len(out) < length:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + label + seed, hashlib.sha256).digest()
    return out[:length]


def session_keys(client_random: bytes, server_random: bytes):
    """Derive the TLS-PSK session keys for suite 0x00AE.

    RFC 4279 premaster for a pure-PSK suite is len||zeros||len||psk. The key
    block for TLS_PSK_WITH_AES_128_CBC_SHA256 is two 32-byte MAC keys then two
    16-byte cipher keys; TLS 1.2 carries the IV explicitly per record.
    """
    n = len(PSK)
    premaster = (struct.pack(">H", n) + bytes(n) + struct.pack(">H", n) + PSK)

    master = prf(premaster, b"master secret", client_random + server_random, 48)
    block = prf(master, b"key expansion", server_random + client_random, 96)

    return block[64:80], block[80:96]      # client_write_key, server_write_key


def tls_random(record: bytes, handshake_type: int):
    """Pull the 32-byte random out of a ClientHello/ServerHello record."""
    if record[0] != 0x16 or record[5] != handshake_type:
        raise ValueError(f"Not handshake type {handshake_type}: {record[:8].hex()}")

    return record[11:43]


def establish_tls(device: goodix.Device, tls_client: socket.socket):
    """Relay the handshake through openssl, keeping the randoms.

    openssl is only the TLS server here; application data is decrypted in
    process from the session keys instead of being read back from the
    subprocess's stdout. That avoids depending on how openssl frames what it
    echoes, and keeps the image bytes on one code path we can test offline.
    """
    hello = device.request_tls_connection()
    client_random = tls_random(hello, 0x01)
    tls_client.sendall(hello)

    server_hello = tls_client.recv(4096)
    server_random = tls_random(server_hello, 0x02)
    device.protocol.write(
        goodix.encode_message_pack(server_hello,
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    for _ in range(3):                       # ClientKeyExchange, CCS, Finished
        tls_client.sendall(
            goodix.check_message_pack(device.read(),
                                      goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    device.protocol.write(
        goodix.encode_message_pack(tls_client.recv(4096),
                                   goodix.FLAGS_TRANSPORT_LAYER_SECURITY))

    return session_keys(client_random, server_random)


def decrypt_record(record: bytes, key: bytes):
    """AES-128-CBC with an explicit IV, then strip padding and the MAC."""
    if record[0] != 0x17:
        raise ValueError(f"Not application data: {record[0]:#04x}")

    body = record[5:]
    plain = AES.new(key, AES.MODE_CBC, body[:16]).decrypt(body[16:])

    pad = plain[-1]
    if pad + 1 > len(plain) or any(b != pad for b in plain[-(pad + 1):]):
        raise ValueError("Bad CBC padding -- wrong key?")

    return plain[:-(pad + 1)][:-32]         # drop padding, then HMAC-SHA256


def wait_for_finger(device: goodix.Device, template: bytes, timeout: float = 30):
    """Arm finger detection and block until the sensor reports a touch.

    The sensor answers fdt_down only once a finger lands, which is well past
    the 5 s default USB read timeout, so poll instead of waiting in one read.
    """
    device.mcu_switch_to_fdt_down(template, False)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return goodix.check_message_protocol(
                goodix.check_message_pack(device.read(timeout=2)),
                goodix.COMMAND_MCU_SWITCH_TO_FDT_DOWN)
        except usb.core.USBTimeoutError:
            continue

    raise TimeoutError("No finger detected")


def capture(device: goodix.Device, key: bytes, flags: int, gain: int):
    """One frame: enable capture, request an image, disable capture."""
    device.write_sensor_register(CAPTURE_REGISTER, CAPTURE_ON)

    frame = device.mcu_get_image(
        struct.pack("<BBBB", flags, 0x06, gain, 0x00),
        goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)

    device.write_sensor_register(CAPTURE_REGISTER, CAPTURE_OFF)

    # a 9-byte header then one TLS application-data record
    plain = decrypt_record(frame[9:], key)
    print(f"  gain {gain:#04x}: {len(frame)} B encrypted -> {len(plain)} B plain")
    if len(plain) < IMAGE_BYTES:
        raise ValueError(f"Short decrypt: {len(plain)} < {IMAGE_BYTES}")

    return tool.decode_image(plain[:IMAGE_BYTES])


def flat_field(frame: list[int], reference: list[int]):
    """Subtract a*reference+b, a and b by least squares.

    Fitting the scale absorbs the gain difference between the reference and
    the live capture, so one reference frame serves every exposure.
    """
    mean_frame = statistics.mean(frame)
    mean_reference = statistics.mean(reference)
    variance = sum((v - mean_reference)**2 for v in reference) or 1

    a = sum((frame[i] - mean_frame) * (reference[i] - mean_reference)
            for i in range(len(frame))) / variance
    b = mean_frame - a * mean_reference

    return [int(frame[i] - (a * reference[i] + b)) for i in range(len(frame))]


def run_driver(device: goodix.Device):
    errors = open("/tmp/openssl-53xc.log", "w+b")
    tls_server = subprocess.Popen([
        "openssl", "s_server", "-nocert", "-psk",
        PSK.hex(), "-port", "4433", "-quiet"
    ],
                                  stdout=subprocess.PIPE,
                                  stderr=errors)

    try:
        success, number = device.reset(True, False, 20)
        if not success:
            raise ValueError("Reset failed")
        print(f"Reset OK, number {number}")

        chip_id = device.read_sensor_register(0x0000, 4)
        print(f"Chip ID: {chip_id.hex(' ')}")

        otp = device.read_otp()
        if len(otp) < 32:
            raise ValueError("Invalid OTP")
        print(f"OTP: {otp.hex(' ')}")

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))

        try:
            client_write_key, _ = establish_tls(device, tls_client)
            device.tls_successfully_established()
            print("TLS established")

            if not device.upload_config_mcu(DEVICE_CONFIG):
                raise ValueError("Failed to upload config")

            template = measure_baseline(device)
            print(f"FDT template: {template.hex(' ')}")

            print("Capturing reference frame (no finger)...")
            reference = capture(device, client_write_key, 0x01, 0xc2)

            device.mcu_switch_to_sleep_mode()
            device.query_mcu_state(b"\x01\x00\x01", False)

            print("Waiting for finger -- touch the sensor...")
            wait_for_finger(device, FDT_DOWN_ARMED + template)
            device.mcu_switch_to_fdt_mode(FDT_MODE_ARMED + template, True)

            image = capture(device, client_write_key, 0x41, 0x86)

            device.mcu_switch_to_fdt_up(FDT_UP_ARMED + template)

            corrected = flat_field(image, reference)
            tool.write_pgm(corrected, SENSOR_WIDTH, SENSOR_HEIGHT,
                           "fingerprint.pgm")
            print("Wrote fingerprint.pgm")

        finally:
            tls_client.close()
    finally:
        tls_server.terminate()


def main(product: int):
    device = init_device(product)
    run_driver(device)
