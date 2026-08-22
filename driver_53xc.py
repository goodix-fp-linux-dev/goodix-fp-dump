"""
Driver for the Goodix 53xc GTLS sensor family (USB PID 0x530c/0x533c/0x538c).

Reverse-engineered from the closed libfprint-tod blob shipped for Ubuntu/
Canonical OEM images (`libfprint-tod-goodix-53xc`, package
`libfprint-2-tod1-goodix`), plus a live USB capture of that blob's own
traffic against real hardware. Full methodology, static analysis notes,
and a working end-to-end capture script:
https://github.com/daemonhorn/goodix-533c-re

Confirmed against real hardware for PID 0x533c only. 0x530c/0x538c share
the same firmware/command set in the same .so (five other named
DEVICE_CONFIG templates exist alongside the "MilanFn" one used here -- see
goodix-533c-re/findings/device-config.md), but their constants were not
extracted or tested; treat this file as a starting point for those PIDs,
not a working driver for them.

Device-specific quirk (533c): unlike every other model in this repo, this
firmware does not reply with a fixed [ack][data] pair for `reset`,
`mcu_switch_to_fdt_mode`, `write_sensor_register`, or `mcu_get_image`'s
ack -- responses have been observed in ack-then-data order, data-then-ack
order, and with duplicated packets. goodix.Device's equivalent methods
assume the fixed order and raise ValueError against this chip. The
tolerant_* helpers below classify each USB read by its decoded command
rather than assuming position, and are used in place of the equivalent
Device methods for just those commands.
"""
import select
import socket
import struct
import subprocess
import time

import goodix
import protocol
import tool

TARGET_FIRMWARE = "GF5288_GM168SEC_APP_13016"

# Confirmed via a live capture of the closed blob's own traffic: this
# unit's PSK was already correctly provisioned to all-zero from the
# factory -- COMMAND_PRESET_PSK_WRITE_R was never observed in that
# capture, and this all-zero PSK's PMK_HASH matched what the device
# already had stored. This driver does not implement PSK writing.
PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PMK_HASH = bytes.fromhex(
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")

# NOTE for anyone implementing PSK writing for this chip: its
# COMMAND_PRESET_PSK_WRITE_R response uses the OPPOSITE success
# convention from every other model in this repo -- message[0] == 0x01
# means success here, not the 0x00 that goodix.Device.preset_psk_write()
# checks for. Found by observing a write that goodix.py logged as
# "failed" actually take effect (the PSK read back correctly afterward,
# and the real vendor driver never rewrote it on a later run). Do not
# reuse Device.preset_psk_write()'s return value unmodified for this chip.

# Extracted from libfprint-tod-goodix-53xc-0.0.4.so's rodata, offset
# 0x103380 (the "MilanFn" config template; five other named sibling
# templates exist in the same blob for other 53xc PIDs/variants -- see
# goodix-533c-re/findings/device-config.md). This is a template, not a
# ready-to-send config: its last 2 bytes are a placeholder checksum, not
# a valid one, matching the pattern in driver_53x5.py's
# DEFAULT_CONFIG/fix_config_checksum. No OTP-derived calibration data is
# spliced in here (unlike 53x5's TCODE_TAG/DAC_L_TAG patching) -- a
# checksum fix alone was confirmed sufficient to get upload_config_mcu()
# accepted and produce a real image, but calibration quality with a
# finger actually present has not been evaluated.
DEFAULT_CONFIG = bytes.fromhex(
    "6011607124952cc114d510e500e514f9030402000008001111ba000180ca000700"
    "8400c0b38600bbc48800baba8a00b2b28c00aaaa8e00c1c19000bbbb9200b1b194"
    "0000a8960000b6980000bf9a0000ba50000105d000000070000000720078567400"
    "34122600001220001040120003042a0102002200012024003200800001005c0080"
    "00560008205800010032002c028200800cba000180ca0007002a01820320001040"
    "2200012024001400800005005c0000015600082058000300820080152a0108005c"
    "0080006200090364001800220000202a0108005c00800052000800000000000000"
    "00000000000000fdf02e2e2f73656e736f722f4d696c616e46")


def fix_config_checksum(config: bytearray):
    """Seed 0xa5a5, running 16-bit LE sum over bytes [0:254], negated mod
    0x10000, stored LE in bytes [254:256]. Matches driver_53x5.py's
    fix_config_checksum exactly; confirmed via disassembly of this .so
    (VA 0x2d0a0) and required since DEFAULT_CONFIG's stored checksum is
    stale template data, not a checksum of the template as-is."""
    checksum = 0xa5a5
    for i in range(0, 254, 2):
        checksum = (checksum + int.from_bytes(config[i:i + 2], "little")) & 0xffff
    checksum = (0x10000 - checksum) & 0xffff
    config[254:256] = checksum.to_bytes(2, "little")


_config = bytearray(DEFAULT_CONFIG)
fix_config_checksum(_config)
DEVICE_CONFIG = bytes(_config)

# Not a confirmed firmware constant -- static analysis of this .so found
# no SENSOR_WIDTH/HEIGHT for this PID (see goodix-533c-re/findings/
# dims-and-inventory.md). Strongly shape-corroborated from a live capture
# instead: of the 12 plausible (width, height) factorizations of the
# resulting 9504-pixel decoded image, only width=108 reshapes into a
# coherent 2D shape (a rounded vignette matching a capacitive sensor's
# physical active area); every other candidate is pure horizontal banding
# with no 2D structure -- the signature of reshaping row-major data at
# the wrong row length. This also exactly matches driver_53x5.py's
# SENSOR_WIDTH=108/SENSOR_HEIGHT=88, suggesting 530c/533c/538c may share
# that sensor's physical die. Treat as likely, not certain.
SENSOR_WIDTH = 108
SENSOR_HEIGHT = 88


def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)
    device.nop()
    return device


def check_psk(device: goodix.Device):
    ok, flags, pmk_hash = device.preset_psk_read(0xbb020001, len(PMK_HASH), 0)
    return ok and pmk_hash == PMK_HASH


def _tolerant_read(device: goodix.Device, command: int, expect_data: bool):
    """Drain packets until one ACK and (if expect_data) one data response
    for `command` have been seen, discarding any duplicate/orphaned
    extras -- order-agnostic, classifying each read by decoded command
    rather than assuming position. Returns the data payload (or None)."""
    ack_payload = None
    data_payload = None
    misses = 0
    while misses < 2 and (ack_payload is None or
                           (expect_data and data_payload is None)):
        try:
            raw = device.protocol.read(timeout=1)
        except Exception:
            misses += 1
            continue

        try:
            inner, _flags, _length = goodix.decode_message_pack(raw)
            payload, cmd, _plen = goodix.decode_message_protocol(inner)
        except Exception:
            continue

        if cmd == goodix.COMMAND_ACK and ack_payload is None:
            ack_payload = payload
        elif cmd == command and data_payload is None:
            data_payload = payload

    if ack_payload is not None:
        goodix.check_ack(ack_payload, command)

    return data_payload


def tolerant_reset(device: goodix.Device, reset_sensor: bool,
                    soft_reset_mcu: bool, sleep_time: int):
    payload = (struct.pack("<B", (0x1 if reset_sensor else 0x0) |
                            (0x1 if soft_reset_mcu else 0x0) << 1 |
                            (0x1 if reset_sensor else 0x0) << 2) +
               struct.pack("<B", sleep_time))
    device.protocol.write(
        goodix.encode_message_pack(
            goodix.encode_message_protocol(payload, goodix.COMMAND_RESET)))

    message = _tolerant_read(device, goodix.COMMAND_RESET,
                              expect_data=not soft_reset_mcu)
    if soft_reset_mcu:
        return None
    if message is None or len(message) < 3 or message[0] != 0x01:
        return False, None
    return True, struct.unpack("<H", message[1:3])[0]


def tolerant_fdt_mode(device: goodix.Device, mode: bytes, reply: bool):
    device.protocol.write(
        goodix.encode_message_pack(
            goodix.encode_message_protocol(
                mode, goodix.COMMAND_MCU_SWITCH_TO_FDT_MODE)))
    return _tolerant_read(device, goodix.COMMAND_MCU_SWITCH_TO_FDT_MODE,
                           expect_data=reply)


def tolerant_write_sensor_register(device: goodix.Device, address: int,
                                    value: bytes):
    message = b"\x00" + struct.pack("<H", address) + value
    device.protocol.write(
        goodix.encode_message_pack(
            goodix.encode_message_protocol(
                message, goodix.COMMAND_WRITE_SENSOR_REGISTER)))
    _tolerant_read(device, goodix.COMMAND_WRITE_SENSOR_REGISTER,
                   expect_data=False)


def tolerant_get_image(device: goodix.Device, payload: bytes, flags: int):
    """goodix.Device.mcu_get_image() also assumes a fixed [ack][data]
    order; read both manually instead of relying on it."""
    device.protocol.write(
        goodix.encode_message_pack(
            goodix.encode_message_protocol(payload,
                                           goodix.COMMAND_MCU_GET_IMAGE)))
    device.protocol.read()  # ACK (ignored -- see module docstring)
    resp = device.protocol.read()  # image data
    return goodix.check_message_pack(resp, flags)


def run_driver(device: goodix.Device):
    """Assumes tolerant_reset() has already been called successfully --
    see main(), which must reset before checking PSK state (this chip
    doesn't respond reliably, including to firmware_version(), until
    after a reset)."""
    # -ign_eof (and keeping stdin open for the subprocess's whole
    # lifetime, never letting it see EOF) is required: without it,
    # openssl s_server sends close_notify as soon as its stdin sees EOF,
    # which happens well before mcu_get_image's Application Data record
    # arrives -- there are several seconds of USB round-trips in between
    # (upload_config_mcu, two fdt_mode calls, write_sensor_register). The
    # session is already closed server-side by the time the image
    # arrives, and openssl silently discards records on a closed session,
    # producing zero decrypted bytes with no visible error. See
    # goodix-533c-re/findings/image-capture-success.md for the full
    # diagnosis.
    #
    # -cipher PSK-AES128-CBC-SHA256:@SECLEVEL=0 forces the real vendor
    # driver's negotiated suite (TLS_PSK_WITH_AES_128_CBC_SHA256,
    # 0x00AE) -- a legacy CBC suite OpenSSL 3.x won't offer by default.
    tls_server = subprocess.Popen(
        ["openssl", "s_server", "-nocert", "-psk", PSK.hex(), "-port",
         "4433", "-quiet", "-ign_eof", "-cipher",
         "PSK-AES128-CBC-SHA256:@SECLEVEL=0"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

    try:
        device.read_sensor_register(0x0000, 4)  # chip ID
        device.read_otp()

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))

        try:
            tool.connect_device(device, tls_client)

            if not device.upload_config_mcu(DEVICE_CONFIG):
                raise ValueError("Failed to upload config")

            tolerant_fdt_mode(
                device,
                b"\x0d\x01\x28\x01\x22\x01\x28\x01\x24\x01\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                False)
            tolerant_fdt_mode(
                device,
                b"\x0d\x01\x28\x01\x22\x01\x28\x01\x24\x01\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                True)

            tolerant_write_sensor_register(device, 0x022c, b"\x0a\x03")

            resp = tolerant_get_image(
                device, b"\x01\x03\x28\x01\x22\x01\x28\x01\x24\x01",
                goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)
            tls_client.sendall(resp[9:])

            # Drain whatever openssl decrypted; the exact byte count
            # isn't a known firmware constant (see SENSOR_WIDTH note
            # above), so poll with a deadline instead of a fixed-size
            # blocking read.
            raw = b""
            deadline = time.time() + 6
            while time.time() < deadline:
                ready, _, _ = select.select([tls_server.stdout], [], [], 0.5)
                if ready:
                    chunk = tls_server.stdout.read1(65536)
                    if not chunk:
                        break
                    raw += chunk
                elif raw:
                    break

            if not raw:
                raise ValueError("No plaintext image data decrypted")

            trimmed = raw[:len(raw) - (len(raw) % 6)]
            tool.write_pgm(tool.decode_image(trimmed), SENSOR_WIDTH,
                           SENSOR_HEIGHT, "clear-0.pgm")

        finally:
            tls_client.close()
    finally:
        tls_server.terminate()


def main(product: int):
    # firmware_version() and other commands are unreliable on this chip
    # until after a reset -- reset first, tolerantly, before anything
    # else (including check_psk below). This ordering was found the hard
    # way: an early version of this driver called firmware_version()
    # immediately after nop() and got ValueError("Invalid message
    # protocol") from every subsequent command, which looked like a wedged
    # device but was actually just this same response-ordering quirk
    # affecting firmware_version() too.
    device = init_device(product)

    reset_ok, _number = tolerant_reset(device, True, False, 20)
    if not reset_ok:
        raise ValueError("Reset failed")

    if not check_psk(device):
        raise ValueError(
            "PSK not provisioned as expected on this device -- this "
            "driver does not implement PSK writing for the 53xc family "
            "(see the note above on its inverted write-ack convention)")

    run_driver(device)
