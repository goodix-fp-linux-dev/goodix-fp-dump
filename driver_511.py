from random import randint
from re import fullmatch
from socket import socket
from subprocess import PIPE, STDOUT, Popen

from crcmod.predefined import mkCrcFun

from goodix import FLAGS_TRANSPORT_LAYER_SECURITY, Device
from protocol import USBProtocol
from tool import connect_device, decode_image, warning, write_pgm

TARGET_FIRMWARE: str = "GF_ST411SEC_APP_12109"
IAP_FIRMWARE: str = "MILAN_ST411SEC_IAP_12101"
VALID_FIRMWARE: str = "GF_ST411SEC_APP_121[0-9]{2}"

PSK: bytes = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX: bytes = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH: bytes = bytes.fromhex(
    "ba1a86037c1d3c71c3af344955bd69a9a9861d9e911fa24985b677e8dbd72d43")

DEVICE_CONFIG: bytes = bytes.fromhex(
    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca000400840015b3860000"
    "c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000"
    "b6980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c008000560004205800030232000c02660003007c000058820080152a0182"
    "032200012024001400800001005c000001560004205800030232000c02660003"
    "007c0000588200801f2a0108005c008000540010016200040364001900660003"
    "007c0001582a0108005c0000015200080054000001660003007c00015800892e")

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 88


def init_device(product: int) -> Device:
    device = Device(product, USBProtocol)

    device.nop()
    device.enable_chip(True)
    device.nop()

    return device


def check_psk(device: Device) -> bool:
    reply = device.preset_psk_read(0xbb020003)
    if not reply[0]:
        raise ValueError("Failed to read PSK")

    if reply[1] != 0xbb020003:
        raise ValueError("Invalid flags")

    return reply[2] == PMK_HASH


def write_psk(device: Device) -> bool:
    if not device.preset_psk_write(0xbb010003, PSK_WHITE_BOX):
        return False

    if not check_psk(device):
        return False

    return True


def erase_firmware(device: Device) -> None:
    device.mcu_erase_app(0, False)
    device.disconnect()


def update_firmware(device: Device) -> None:
    firmware_file = open(f"firmware/511/{TARGET_FIRMWARE}.bin", "rb")
    firmware = firmware_file.read()
    firmware_file.close()

    try:
        length = len(firmware)
        for i in range(0, length, 1008):
            if not device.write_firmware(i, firmware[i:i + 1008]):
                raise ValueError("Failed to write firmware")

        if not device.check_firmware(0, length,
                                     mkCrcFun("crc-32-mpeg")(firmware)):
            raise ValueError("Failed to check firmware")

    except Exception as error:
        print(
            warning(f"The program went into serious problems while trying to "
                    f"update the firmware: {error}"))

        erase_firmware(device)

        raise error

    device.reset(False, True, 20)
    device.disconnect()


def run_driver(device: Device):
    tls_server = Popen([
        "openssl", "s_server", "-nocert", "-psk",
        PSK.hex(), "-port", "4433", "-quiet"
    ],
                       stdout=PIPE,
                       stderr=STDOUT)

    try:
        if not device.reset(True, False, 20)[0]:
            raise ValueError("Reset failed")

        device.read_sensor_register(0x0000, 4)  # Read chip ID (0x2504)

        otp = device.read_otp()
        if len(otp) < 64:
            raise ValueError("Invalid OTP")

        # OTP 0: 5332383733342e0032778aa2d495ca05
        #        5107050a7d0bfd274103110cf17f800c
        #        38813034a57f5ef406c4bd4201bdb7b9
        #        b7b7b7b9b7b73230a55a5ea1850cfd71
        # OTP 1: 5332423937332e000a777aa3452cec02
        #        510705027d4bd5274103d10cf18f700c
        #        38c13033a58f5ff407f48e71018eb6b7
        #        b6b6b6b7b6b63450a55a5fa0c814d548

        otp_cp_data = b""
        otp_cp_data += otp[0:11]
        otp_cp_data += otp[36:40]
        if ~mkCrcFun("crc-8")(otp_cp_data) & 0xff != otp[60]:
            raise ValueError("Invalid OTP CP data checksum")

        otp_mt_data = b""
        otp_mt_data += otp[20:28]
        otp_mt_data += otp[29:36]
        otp_mt_data += otp[40:50]
        otp_mt_data += otp[54:56]
        if ~mkCrcFun("crc-8")(otp_mt_data) & 0xff != otp[63]:
            raise ValueError("Invalid OTP MT data checksum")

        otp_ft_data = b""
        otp_ft_data += otp[11:20]
        otp_ft_data += otp[28:29]
        otp_ft_data += otp[50:54]
        otp_ft_data += otp[56:60]
        otp_ft_data += otp[62:63]
        if ~mkCrcFun("crc-8")(otp_ft_data) & 0xff != otp[61]:
            raise ValueError("Invalid OTP FT data checksum")

        # OTP 0 cp data: 5332383733342e0032778aa57f5ef4
        # OTP 1 cp data: 5332423937332e000a777aa58f5ff4

        # OTP 0 mt data: 7d0bfd274103110c7f800c3881303406c4bd4201bdb7b9b7b73230
        # OTP 1 mt data: 7d4bd5274103d10c8f700c38c1303307f48e71018eb6b7b6b63450

        # OTP 0 ft data: a2d495ca055107050af1b7b9b7b7a55a5ea1fd
        # OTP 1 ft data: a3452cec0251070502f1b6b7b6b6a55a5fa0d5

        if not device.reset(True, False, 20)[0]:
            raise ValueError("Reset failed")

        device.mcu_switch_to_idle_mode(20)

        # From OTP 0 : DAC0=0xb78, DAC1=0xb9, DAC2=0xb7, DAC3=0xb7, b7b9b7b7
        # From OTP 1 : DAC0=0xb68, DAC1=0xb7, DAC2=0xb6, DAC3=0xb6, b6b7b6b6

        device.write_sensor_register(0x0220, b"\x78\x0b")  # DAC0=0xb78
        device.write_sensor_register(0x0236, b"\xb9\x00")  # DAC1=0xb9
        device.write_sensor_register(0x0238, b"\xb7\x00")  # DAC2=0xb7
        device.write_sensor_register(0x023a, b"\xb7\x00")  # DAC3=0xb7

        if not device.upload_config_mcu(DEVICE_CONFIG):
            raise ValueError("Failed to upload config")

        if not device.set_powerdown_scan_frequency(100):
            raise ValueError("Failed to set powerdown scan frequency")

        tls_client = socket()
        tls_client.connect(("localhost", 4433))

        try:
            connect_device(device, tls_client)

            device.tls_successfully_established()

            device.query_mcu_state(b"\x55", True)

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\xae\xae\xbf\xbf\xa4\xa4"
                b"\xb8\xb8\xa8\xa8\xb7\xb7", True)

            device.nav_0()

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x80\xaf\x80\xbf\x80\xa3"
                b"\x80\xb7\x80\xa7\x80\xb6", True)

            device.read_sensor_register(0x0082, 2)

            tls_client.sendall(
                device.mcu_get_image(b"\x01\x00",
                                     FLAGS_TRANSPORT_LAYER_SECURITY))

            write_pgm(decode_image(tls_server.stdout.read(10573)[8:-5]),
                      SENSOR_WIDTH, SENSOR_HEIGHT, "clear.pgm")

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x80\xaf\x80\xbf\x80\xa4"
                b"\x80\xb8\x80\xa8\x80\xb7", True)

            print("Waiting for finger...")

            device.mcu_switch_to_fdt_down(
                b"\x0c\x01\x80\xaf\x80\xbf\x80\xa4"
                b"\x80\xb8\x80\xa8\x80\xb7", True)

            tls_client.sendall(
                device.mcu_get_image(b"\x01\x00",
                                     FLAGS_TRANSPORT_LAYER_SECURITY))

            write_pgm(decode_image(tls_server.stdout.read(10573)[8:-5]),
                      SENSOR_WIDTH, SENSOR_HEIGHT, "fingerprint.pgm")

        finally:
            tls_client.close()
    finally:
        tls_server.terminate()


def main(product: int) -> None:
    print(
        warning("This program might break your device.\n"
                "Consider that it may flash the device firmware.\n"
                "Continue at your own risk.\n"
                "But don't hold us responsible if your device is broken!\n"
                "Don't run this program as part of a regular process."))

    code = randint(0, 9999)

    if input(f"Type {code} to continue and confirm that you are not a bot: "
            ) != str(code):
        print("Abort")
        return

    previous_firmware = None

    device = init_device(product)

    while True:
        firmware = device.firmware_version()
        print(f"Firmware: {firmware}")

        valid_psk = check_psk(device)
        print(f"Valid PSK: {valid_psk}")

        if firmware == previous_firmware:
            raise ValueError("Unchanged firmware")

        previous_firmware = firmware

        if fullmatch(TARGET_FIRMWARE, firmware):
            if not valid_psk:
                erase_firmware(device)

                device = init_device(product)

                continue

            run_driver(device)
            return

        if fullmatch(VALID_FIRMWARE, firmware):
            erase_firmware(device)

            device = init_device(product)

            continue

        if fullmatch(IAP_FIRMWARE, firmware):
            if not valid_psk:
                if not write_psk(device):
                    raise ValueError("Failed to write PSK")

            update_firmware(device)

            device = init_device(product)

            continue

        raise ValueError("Invalid firmware\n" +
                         warning("Please consider that removing this security "
                                 "is a very bad idea!"))
