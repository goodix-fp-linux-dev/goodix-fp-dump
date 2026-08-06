import hashlib

import goodix
import protocol

# what preset_psk_read reports when the sensor holds the all-zero PSK that
# driver_51x7 / driver_55x4 provision -- worth knowing before writing one
ALL_ZERO_PSK_HASH = hashlib.sha256(bytes(32)).digest()


def dump_firmware(device: goodix.Device, chunk: int = 256, limit: int = 0x80000):
    """Read the running firmware back off the sensor, until it stops replying.

    This is the prerequisite for any provisioning work: mcu_erase_app is
    irreversible without an image to flash back, and upstream ships none
    (firmware/ is empty, *.bin is gitignored).
    """
    data = b""
    while len(data) < limit:
        try:
            block = device.read_firmware(len(data), chunk)
        except Exception as exception:
            print(f"  stopped at {len(data):#x}: "
                  f"{type(exception).__name__}: {exception}")
            break

        if not block:
            break

        data += block

    return data


def attempt(label: str, function):
    try:
        return function()
    except Exception as exception:
        print(f"{label}: FAILED {type(exception).__name__}: {exception}")
        return None


def main(product: int):
    """Read-only reconnaissance: firmware, PSK state, OTP, firmware readback.

    No firmware erase and no PSK write -- nothing here can brick the sensor.
    """
    device = goodix.Device(product, protocol.USBProtocol)

    device.nop()
    attempt("Enable chip", lambda: device.enable_chip(True))
    device.nop()

    firmware = attempt("Firmware", device.firmware_version)
    print(f"Firmware: {firmware}")

    # preset_psk_read needs length and offset: without them goodix.py sends the
    # short form and the sensor answers "not present" even when a PSK is there.
    # Slots differ per sensor; 533c answers 0xbb020001 (hash) and 0xbb010002.
    for flags, length in ((0xbb020001, 32), (0xbb010002, 102),
                          (0xbb020003, 32), (0xbb020007, 32)):
        result = attempt(f"PSK {flags:#x}",
                         lambda: device.preset_psk_read(flags, length, 0))
        if result is None:
            continue

        success, reply_flags, data = result
        if not success:
            print(f"PSK {flags:#x}: not present")
            continue

        note = ""
        if data == ALL_ZERO_PSK_HASH:
            note = "  <- sha256 of 32 zero bytes: sensor holds the all-zero PSK"
        print(f"PSK {flags:#x}: flags={reply_flags:#x} "
              f"data({len(data)})={data.hex()}{note}")

    attempt("Reset", lambda: device.reset(True, False, 20))

    chip_id = attempt("Chip ID", lambda: device.read_sensor_register(0x0000, 4))
    if chip_id is not None:
        print(f"Chip ID: {chip_id.hex(' ')}")

    otp = attempt("OTP", device.read_otp)
    if otp is not None:
        print(f"OTP ({len(otp)} bytes): {otp.hex(' ')}")

    print("Dumping firmware...")
    image = dump_firmware(device)
    print(f"Firmware dumped: {len(image)} bytes")

    if image:
        path = f"firmware/{firmware}.bin"
        with open(path, "wb") as file:
            file.write(image)
        print(f"Wrote {path}")
