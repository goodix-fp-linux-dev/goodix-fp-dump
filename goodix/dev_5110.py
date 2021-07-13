from os.path import join
from re import fullmatch
from socket import socket
from time import sleep
from typing import List

from crcmod.predefined import mkCrcFun

from .core import (FLAGS_TRANSPORT_LAYER_SECURITY, Device, check_message_pack,
                   encode_message_pack)

TARGET_PSK: bytes = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

TARGET_PSK_WB: bytes = bytes.fromhex(
    "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001c849b9831e694c"
    "b3ef601ff3e13c3c040000004000000054006800690073002000690073002000"
    "74006800650020006400650073006300720069007000740069006f006e002000"
    "73007400720069006e0067002e0000001066000000010000200000003ff07b38"
    "3d00fb003592b4c8fa6aab2e17a172409ad745d3b6464274a662df1500000000"
    "0e80000000020000200000003cd09ee49c63e336c144d125842ae92ad50b53cf"
    "8dfd104971475b74f90d9d833000000064c19ffff8280ec919533bfb5f7bf3b4"
    "18632c4544c66d3af8341a4f24ac7cdeafbe52d2d03848d5e70bc7fe3ce0f295"
    "4000000070583734b732ceed6aae6df5338908931d73baafb96950af4fd8d546"
    "da11f7a18c86b8fb06bc6a96247840f884e354e24128e61739991717fa1c6e91"
    "60960399d7b9450b7c3547b1030001bb60000000ec35ae3abb45ed3f12c4751f"
    "1e5c2cc05b3c5452e9104d9f2a3118644f37a04b6fd66b1d97cf80f1345f76c8"
    "4f03ff30bb51bf308f2a9875c41e6592cd2a2f9e60809b17b5316037b69bb2fa"
    "5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

TARGET_PMK_HASH: bytes = bytes.fromhex(
    "ba1a86037c1d3c71c3af344955bd69a9a9861d9e911fa24985b677e8dbd72d43")

TARGET_FIRMWARE: str = "GF_ST411SEC_APP_12109"
IAP_FIRMWARE: str = "MILAN_ST411SEC_IAP_12101"
VALID_FIRMWARE: str = "GF_ST411SEC_APP_121[0-9]{2}"

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 88


def init_device(device: Device) -> None:
    device.nop()
    device.enable_chip()
    device.nop()

    print("Device init: OK")


def setup_device(device: Device) -> None:
    device.reset()

    device.read_sensor_register(0x0000, 4)  # Read chip ID (0x2504)

    device.read_otp(
    )  # OTP: 0x5332383733342e0032778aa2d495ca055107050a7d0bfd274103110cf17f800c38813034a57f5ef406c4bd4201bdb7b9b7b7b7b9b7b73230a55a5ea1850cfd71

    # OTP cp data: 0x5332383733342e0032778aa57f5ef4
    # CRC checksum: 133

    # OTP mt data: 0x7d0bfd274103110c7f800c3881303406c4bd4201bdb7b9b7b73230
    # CRC checksum: 113

    # OTP ft data: 0xa2d495ca055107050af1b7b9b7b7a55a5ea1fd
    # CRC checksum: 12

    device.reset()

    device.mcu_switch_to_idle_mode()

    # From otp: DAC0=0xb78, DAC1=0xb9, DAC2=0xb7, DAC3=0xb7

    device.write_sensor_register(0x0220, b"\x78\x0b")  # DAC0=0xb78
    device.write_sensor_register(0x0236, b"\xb9\x00")  # DAC1=0xb9
    device.write_sensor_register(0x0238, b"\xb7\x00")  # DAC2=0xb7
    device.write_sensor_register(0x023a, b"\xb7\x00")  # DAC3=0xb7

    device.upload_config_mcu(
        b"\x70\x11\x60\x71\x2c\x9d\x2c\xc9\x1c\xe5\x18\xfd\x00\xfd\x00\xfd"
        b"\x03\xba\x00\x01\x80\xca\x00\x04\x00\x84\x00\x15\xb3\x86\x00\x00"
        b"\xc4\x88\x00\x00\xba\x8a\x00\x00\xb2\x8c\x00\x00\xaa\x8e\x00\x00"
        b"\xc1\x90\x00\xbb\xbb\x92\x00\xb1\xb1\x94\x00\x00\xa8\x96\x00\x00"
        b"\xb6\x98\x00\x00\x00\x9a\x00\x00\x00\xd2\x00\x00\x00\xd4\x00\x00"
        b"\x00\xd6\x00\x00\x00\xd8\x00\x00\x00\x50\x00\x01\x05\xd0\x00\x00"
        b"\x00\x70\x00\x00\x00\x72\x00\x78\x56\x74\x00\x34\x12\x20\x00\x10"
        b"\x40\x2a\x01\x02\x04\x22\x00\x01\x20\x24\x00\x32\x00\x80\x00\x01"
        b"\x00\x5c\x00\x80\x00\x56\x00\x04\x20\x58\x00\x03\x02\x32\x00\x0c"
        b"\x02\x66\x00\x03\x00\x7c\x00\x00\x58\x82\x00\x80\x15\x2a\x01\x82"
        b"\x03\x22\x00\x01\x20\x24\x00\x14\x00\x80\x00\x01\x00\x5c\x00\x00"
        b"\x01\x56\x00\x04\x20\x58\x00\x03\x02\x32\x00\x0c\x02\x66\x00\x03"
        b"\x00\x7c\x00\x00\x58\x82\x00\x80\x1f\x2a\x01\x08\x00\x5c\x00\x80"
        b"\x00\x54\x00\x10\x01\x62\x00\x04\x03\x64\x00\x19\x00\x66\x00\x03"
        b"\x00\x7c\x00\x01\x58\x2a\x01\x08\x00\x5c\x00\x00\x01\x52\x00\x08"
        b"\x00\x54\x00\x00\x01\x66\x00\x03\x00\x7c\x00\x01\x58\x00\x89\x2e")

    device.set_powerdown_scan_frequency()

    print("Device setup: OK")


def connect_device(device: Device, tls_client: socket) -> None:
    tls_client.sendall(device.request_tls_connection())

    device.write(
        encode_message_pack(tls_client.recv(1024),
                            FLAGS_TRANSPORT_LAYER_SECURITY))

    tls_client.sendall(
        check_message_pack(device.read(), FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        check_message_pack(device.read(), FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        check_message_pack(device.read(), FLAGS_TRANSPORT_LAYER_SECURITY))

    device.write(
        encode_message_pack(tls_client.recv(1024),
                            FLAGS_TRANSPORT_LAYER_SECURITY))

    sleep(0.01)  # Important otherwise an USBTimeout error occur

    device.tls_successfully_established()

    print("Device connect: OK")


def check_psk(device: Device, count: int = 2) -> bool:
    for _ in range(count):
        if device.preset_psk_read_r(0xbb020003) == TARGET_PMK_HASH:
            print("PSK: Valid")
            return True

    print("PSK: Invalid")
    return False


def change_psk(device: Device) -> None:
    device.preset_psk_write_r(0xbb010002, 332, TARGET_PSK_WB)

    print("Change PSK: OK")


def check_firmware(device: Device) -> int:
    firmware = device.firmware_version()
    print(f"Firmware: {firmware}")

    if fullmatch(TARGET_FIRMWARE, firmware):
        return 0

    if fullmatch(VALID_FIRMWARE, firmware):
        return 1

    if fullmatch(IAP_FIRMWARE, firmware):
        return 2

    return -1


def erase_firmware(device: Device) -> None:
    device.mcu_erase_app()
    device.wait_disconnect()

    print("Erase firmware: OK")


def flash_firmware(device: Device, path: str = "firmware/5110") -> None:
    firmware_file = open(join(path, f"{TARGET_FIRMWARE}.bin"), "rb")
    firmware = firmware_file.read()
    firmware_file.close()

    length = len(firmware)

    for i in range(0, length, 1008):
        device.write_firmware(i, firmware[i:i + 1008])

    device.check_firmware(0, len(firmware), mkCrcFun("crc-32-mpeg")(firmware))

    device.reset(False, True)
    device.wait_disconnect()

    print("Flash firmware: OK")


def write_pgm(image: List[int], file_name: str) -> None:
    file = open(f"{file_name}.pgm", "w")

    file.write(f"P2\n{SENSOR_HEIGHT} {SENSOR_WIDTH}\n4095\n")
    file.write("\n".join(map(str, image)))

    file.close()
