import goodix
import protocol


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

    # the flags value differs per sensor: 51x7 uses 0xbb020003, 55x4 0xbb020007
    for flags in (0xbb020003, 0xbb020007, 0xbb020001, 0xbb020002):
        result = attempt(f"PSK {flags:#x}", lambda: device.preset_psk_read(flags))
        if result is None:
            continue

        success, reply_flags, psk_hash = result
        if not success:
            print(f"PSK {flags:#x}: not present")
        else:
            print(f"PSK {flags:#x}: flags={reply_flags:#x} hash={psk_hash.hex()}")

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
