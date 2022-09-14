import logging
import os

import protocol
import wrapless


def main(product: int, target_firmware_name: str):
    if "DEBUG" in os.environ:
        logging.basicConfig(level=logging.DEBUG)

    device = wrapless.Device(product, protocol.USBProtocol)
    device.ping()

    firmware_version = device.read_firmware_version()
    print(f"Firmware version: {firmware_version}")

    _, chip_vendor, kind, _ = firmware_version.split("_")
    if kind != "IAP":
        raise Exception("Chip already has firmware")

    target_chip_vendor = target_firmware_name.split("_")[1]
    if chip_vendor[:2] != target_chip_vendor[:2]:
        raise Exception("Chip vendor does not match")

    with open(f"firmware/53x5/{target_firmware_name}.bin", "rb") as firmware_file:
        firmware = firmware_file.read()

    device.update_firmware(firmware)
