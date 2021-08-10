from hashlib import sha256
from hmac import new as hmac
from random import randint
from re import fullmatch
from socket import socket
from struct import pack as encode
from subprocess import PIPE, STDOUT, Popen
from time import sleep
from typing import List

from crcmod.predefined import mkCrcFun

from goodix import (FLAGS_TRANSPORT_LAYER_SECURITY, Device, check_message_pack,
                    decode_image, encode_message_pack)

TARGET_FIRMWARE: str = "GF5298_GM168SEC_APP_13016"
IAP_FIRMWARE: str = "MILAN_GM168SEC_IAP_10007"
VALID_FIRMWARE: str = "GF5298_GM168SEC_APP_130[0-9]{2}"

PSK: bytes = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX: bytes = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH: bytes = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361")

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


def warning(text: str) -> str:
    decorator = "#" * len(max(text.split("\n"), key=len))
    return f"\033[31;5m{decorator}\n{text}\n{decorator}\033[0m"


def check_psk(device: Device, tries: int = 2) -> bool:
    for _ in range(tries):
        reply = device.preset_psk_read_r(0xbb020001, len(PMK_HASH), 0)
        if not reply[0]:
            raise ValueError("Failed to read PSK")

        if reply[1] != 0xbb020001:
            raise ValueError("Invalid flags")

        if reply[2] == PMK_HASH:
            return True

    return False


def erase_firmware(device: Device) -> None:
    device.mcu_erase_app(50)
    device.wait_disconnect()


def write_firmware(device: Device,
                   offset: int,
                   payload: bytes,
                   tries: int = 2) -> bool:
    for _ in range(tries):
        if device.write_firmware(offset, payload):
            return True

    return False


def update_firmware(device: Device,
                    path: str = "firmware/538",
                    tries: int = 2) -> None:
    try:
        for _ in range(tries):
            firmware_file = open(f"{path}/{TARGET_FIRMWARE}.bin", "rb")
            firmware = firmware_file.read()
            firmware_file.close()

            mod = b""
            for i in range(1, 65):
                mod += encode("<B", i)
            raw_pmk = (encode(">H", len(PSK)) + PSK) * 2
            pmk = sha256(raw_pmk).digest()
            pmk_hmac = hmac(pmk, mod, sha256).digest()
            firmware_hmac = hmac(pmk_hmac, firmware, sha256).digest()

            length = len(firmware)
            for i in range(0, length, 256):
                if not write_firmware(device, i, firmware[i:i + 256]):
                    raise ValueError("Failed to write firmware")

            if device.check_firmware(0, length,
                                     mkCrcFun("crc-32-mpeg")(firmware),
                                     firmware_hmac):
                device.reset(False, True, 50)
                device.wait_disconnect()

                return

        raise ValueError("Failed to check firmware")

    except Exception as error:
        print(
            warning(f"The program went into serious problems while trying to "
                    f"update the firmware: {error}"))

        erase_firmware(device)

        raise error


def setup_device(device: Device) -> None:
    if not device.reset(True, False, 20)[0]:
        raise ValueError("Reset failed")

    device.read_sensor_register(0x0000, 4)  # Read chip ID (0x2504)

    device.read_otp()
    # OTP 0: 0x5332383733342e0032778aa2d495ca055107050a7d0bfd274103110cf17f800c38813034a57f5ef406c4bd4201bdb7b9b7b7b7b9b7b73230a55a5ea1850cfd71
    # OTP 1: 0x5332423937332e000a777aa3452cec02510705027d4bd5274103d10cf18f700c38c13033a58f5ff407f48e71018eb6b7b6b6b6b7b6b63450a55a5fa0c814d548

    # OTP 0 cp data: 0x5332383733342e0032778aa57f5ef4, CRC checksum: 133
    # OTP 1 cp data: 0x5332423937332e000a777aa58f5ff4

    # OTP 0 mt data: 0x7d0bfd274103110c7f800c3881303406c4bd4201bdb7b9b7b73230, CRC checksum: 113
    # OTP 1 mt data: 0x7d4bd5274103d10c8f700c38c1303307f48e71018eb6b7b6b63450

    # OTP 0 ft data: 0xa2d495ca055107050af1b7b9b7b7a55a5ea1fd, CRC checksum: 12
    # OTP 1 ft data: 0xa3452cec0251070502f1b6b7b6b6b6b7b6b6d5

    if not device.reset(True, False, 20)[0]:
        raise ValueError("Reset failed")

    device.mcu_switch_to_idle_mode(20)

    # From OTP 0 : DAC0=0xb78, DAC1=0xb9, DAC2=0xb7, DAC3=0xb7, 0xb7b9b7b7
    # From OTP 1 : DAC0=0xb68, DAC1=0xb7, DAC2=0xb6, DAC3=0xb6, 0xb6b7b6b6

    device.write_sensor_register(0x0220, b"\x78\x0b")  # DAC0=0xb78
    device.write_sensor_register(0x0236, b"\xb9\x00")  # DAC1=0xb9
    device.write_sensor_register(0x0238, b"\xb7\x00")  # DAC2=0xb7
    device.write_sensor_register(0x023a, b"\xb7\x00")  # DAC3=0xb7

    if not device.upload_config_mcu(DEVICE_CONFIG):
        raise ValueError("Failed to upload config")

    if not device.set_powerdown_scan_frequency(100):
        raise ValueError("Failed to set powerdown scan frequency")


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

    device.query_mcu_state()


def get_image(device: Device, tls_client: socket, tls_server: Popen) -> None:
    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\xae\xae\xbf\xbf\xa4\xa4\xb8\xb8\xa8\xa8\xb7\xb7")

    device.nav_0()

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x80\xaf\x80\xbf\x80\xa3\x80\xb7\x80\xa7\x80\xb6")

    device.read_sensor_register(0x0082, 2)

    tls_client.sendall(device.mcu_get_image())

    write_pgm(decode_image(tls_server.stdout.read(10573)[8:-5]), "clear.pgm")

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x80\xaf\x80\xbf\x80\xa4\x80\xb8\x80\xa8\x80\xb7")

    print("Waiting for finger...")

    device.mcu_switch_to_fdt_down(
        b"\x0c\x01\x80\xaf\x80\xbf\x80\xa4\x80\xb8\x80\xa8\x80\xb7")

    tls_client.sendall(device.mcu_get_image())

    write_pgm(decode_image(tls_server.stdout.read(10573)[8:-5]),
              "fingerprint.pgm")


def write_pgm(image: List[int], file_name: str) -> None:
    file = open(file_name, "w")

    file.write(f"P2\n{SENSOR_HEIGHT} {SENSOR_WIDTH}\n4095\n")
    file.write("\n".join(map(str, image)))

    file.close()


def run_driver(device: Device):
    tls_server = Popen([
        "openssl", "s_server", "-nocert", "-psk",
        PSK.hex(), "-port", "4433", "-quiet"
    ],
                       stdout=PIPE,
                       stderr=STDOUT)

    try:
        setup_device(device)

        tls_client = socket()
        tls_client.connect(("localhost", 4433))

        try:
            connect_device(device, tls_client)

            get_image(device, tls_client, tls_server)

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
                "Don't run this program as part of a regular process"))

    code = randint(0, 9999)

    if input(f"Type {code} to continue and confirm that you are not a bot: "
            ) == f"{code}":

        previous_firmware = None
        while True:
            device = Device(product)

            device.nop()

            firmware = device.firmware_version()
            print(f"Firmware: {firmware}")

            valid_psk = check_psk(device)
            print(f"Valid PSK: {valid_psk}")

            print("Return to not flash anything")

            return

            if firmware == previous_firmware:
                raise ValueError("Unchanged firmware")

            previous_firmware = firmware

            if fullmatch(TARGET_FIRMWARE, firmware):
                if not valid_psk:
                    erase_firmware(device)
                    continue

                run_driver(device)
                return

            if fullmatch(VALID_FIRMWARE, firmware):
                erase_firmware(device)
                continue

            if fullmatch(IAP_FIRMWARE, firmware):
                if not valid_psk:
                    device.preset_psk_write_r(0xbb010003, len(PSK_WHITE_BOX),
                                              PSK_WHITE_BOX)

                    if not check_psk(device):
                        raise ValueError("Unchanged PSK")

                write_firmware(device)
                continue

            raise ValueError(
                "Invalid firmware\n" +
                warning("Please consider that removing this security "
                        "is a very bad idea!"))
