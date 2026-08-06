import logging

import usb.util

import goodix
import protocol
import wrapless


def read_firmware_version(device: goodix.Device):
    """Like goodix.Device.firmware_version(), but tolerates sensors that reply
    without a preceding ACK frame -- 533c (GF5288_GM168SEC) does exactly that.
    """
    device.protocol.write(
        goodix.encode_message_pack(
            goodix.encode_message_protocol(b"\x00\x00",
                                           goodix.COMMAND_FIRMWARE_VERSION)))

    while True:
        message = goodix.check_message_pack(device.protocol.read())
        payload, command, _ = goodix.decode_message_protocol(message)

        if command == goodix.COMMAND_ACK:
            continue

        if command != goodix.COMMAND_FIRMWARE_VERSION:
            raise ValueError(f"Unexpected command: {command:#04x}")

        return payload.split(b"\x00")[0].decode()


def identify_wrapless(product: int):
    device = wrapless.Device(product, protocol.USBProtocol)
    try:
        device.ping()
        print(f"Firmware version: {device.read_firmware_version()}")

        device.reset(0, False)
        chip_id = wrapless.decode_u32(device.read_data(0, 4, 0.2))
        print(f"Chip ID: {chip_id:#x}")

    finally:
        usb.util.dispose_resources(device.protocol.device)


def identify_wrapped(product: int):
    device = goodix.Device(product, protocol.USBProtocol)
    try:
        device.nop()
        print(f"Firmware version: {read_firmware_version(device)}")

        device.reset(True, False, 20)
        chip_id = wrapless.decode_u32(device.read_sensor_register(0x0000, 4))
        print(f"Chip ID: {chip_id:#x}")

    finally:
        usb.util.dispose_resources(device.protocol.device)


def main(product: int):
    """Report which message framing a sensor speaks, and its firmware version.

    Read-only: ping, firmware version and register reads only. Nothing here
    erases firmware or writes a PSK.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    for name, identify in (("wrapless", identify_wrapless),
                           ("wrapped", identify_wrapped)):
        print(f"\nTrying {name} protocol...")

        try:
            identify(product)
            print(f"Sensor speaks the {name} protocol")

        except Exception as exception:
            print(f"Not {name}: {type(exception).__name__}: {exception}")
