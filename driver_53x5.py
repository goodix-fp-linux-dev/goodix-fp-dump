import logging
import os

from wrapless import Device, decode_u32
from protocol import USBProtocol
from tool import decode_image, write_pgm

from Crypto.Hash import SHA256

VALID_FIRMWARE: str = "GF5288_HTSEC_APP_10020"

PSK: bytes = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
)

PSK_WHITE_BOX: bytes = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5"
)

SENSOR_WIDTH = 108
SENSOR_HEIGHT = 88


def is_valid_psk(device: Device) -> bool:
    psk_hash = device.read_psk_hash()
    return psk_hash == SHA256.SHA256Hash(PSK).digest()


def write_psk(device: Device):
    print(f"Writing white-box all-zero PSK")
    device.write_psk_white_box(PSK_WHITE_BOX)

    if not is_valid_psk(device):
        raise Exception("Could not set all-zero PSK")


def main(product: int) -> None:
    if "DEBUG" in os.environ:
        logging.basicConfig(level=logging.DEBUG)

    device = Device(product, USBProtocol)
    device.ping()

    firmware_version = device.read_firmware_version()
    print(f"Firmware version: {firmware_version}")
    if firmware_version != VALID_FIRMWARE:
        raise Exception("Chip does not have a valid firmware")

    reg_data = device.read_sensor_register(0, 4, 0.2)
    chip_id = decode_u32(reg_data)
    print(f"Chip ID: {hex(chip_id)}")

    otp = device.read_otp(0.2)
    print(f"OTP: {otp.hex(' ')}")

    print("Checking PSK hash")
    if not is_valid_psk(device):
        print("Updating PSK")
        write_psk(device)
    print("All-zero PSK set up")

    print("Establishing GTLS connection")
    device.establish_gtls_connection(PSK)
    print("Connection successfully established")

    print("Getting image")
    data = device.get_sensor_data(b"\x01\x06\xbe\x00", 1)

    print("Decoding and saving image")
    write_pgm(decode_image(data), SENSOR_HEIGHT, SENSOR_WIDTH, "image.pgm")
