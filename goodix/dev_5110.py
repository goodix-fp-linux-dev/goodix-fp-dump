from os.path import join
from re import fullmatch

from crcmod.predefined import mkCrcFun

from .core import Device

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


def init_device(device: Device) -> None:
    device.nop()
    device.enable_chip()
    device.nop()

    print("Device init: OK")


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
