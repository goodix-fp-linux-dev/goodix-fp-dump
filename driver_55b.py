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

TARGET_FIRMWARE: str = "GF3268_RTSEC_APP_10041"
IAP_FIRMWARE: str = "MILAN_RTSEC_IAP_10027"
VALID_FIRMWARE: str = "GF3268_RTSEC_APP_100[0-9]{2}"

PSK: bytes = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX: bytes = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH: bytes = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361")

DEVICE_CONFIG: bytes = bytes.fromhex("")

SENSOR_WIDTH = 88
SENSOR_HEIGHT = 108


def warning(text: str) -> str:
    decorator = "#" * len(max(text.split("\n"), key=len))
    return f"\033[31;5m{decorator}\n{text}\n{decorator}\033[0m"


def check_psk(device: Device, tries: int = 2) -> bool:
    for _ in range(tries):
        if device.preset_psk_read_r(0xbb020007, 0) == PMK_HASH:
            return True

    return False


def erase_firmware(device: Device) -> None:
    device.mcu_erase_app(0)
    device.wait_disconnect()


def write_firmware(device: Device, path: str = "firmware/55b") -> None:
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
        device.write_firmware(i, firmware[i:i + 256])

    # TODO handle error for check firmware
    device.check_firmware(0, length,
                          mkCrcFun("crc-32-mpeg")(firmware), firmware_hmac)

    device.reset(False, True, 100)
    device.wait_disconnect()


def setup_device(device: Device) -> None:
    device.reset(True, False, 20)

    device.read_sensor_register(0x0000, 4)  # Read chip ID (0x2504)

    device.read_otp()
    # OTP: 0x5332383733342e0032778aa2d495ca055107050a7d0bfd274103110cf17f800c38813034a57f5ef406c4bd4201bdb7b9b7b7b7b9b7b73230a55a5ea1850cfd71

    # OTP cp data: 0x5332383733342e0032778aa57f5ef4
    # CRC checksum: 133

    # OTP mt data: 0x7d0bfd274103110c7f800c3881303406c4bd4201bdb7b9b7b73230
    # CRC checksum: 113

    # OTP ft data: 0xa2d495ca055107050af1b7b9b7b7a55a5ea1fd
    # CRC checksum: 12

    device.reset(True, False, 20)

    device.mcu_switch_to_idle_mode(20)

    # From otp: DAC0=0xb78, DAC1=0xb9, DAC2=0xb7, DAC3=0xb7

    device.write_sensor_register(0x0220, b"\x78\x0b")  # DAC0=0xb78
    device.write_sensor_register(0x0236, b"\xb9\x00")  # DAC1=0xb9
    device.write_sensor_register(0x0238, b"\xb7\x00")  # DAC2=0xb7
    device.write_sensor_register(0x023a, b"\xb7\x00")  # DAC3=0xb7

    device.upload_config_mcu(DEVICE_CONFIG)

    device.set_powerdown_scan_frequency(100)


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

            iap = device.get_iap_version(25)
            print(f"IAP: {iap}")

            if iap != IAP_FIRMWARE:
                raise ValueError(
                    "Invalid IAP: Abort\n" +
                    warning("Please consider that removing this security "
                            "is a very bad idea!"))

            if firmware == previous_firmware:
                raise ValueError("Unchanged firmware")

            previous_firmware = firmware

            if fullmatch(TARGET_FIRMWARE, firmware):
                if not valid_psk:
                    device.preset_psk_write_r(0xbb010003, len(PSK_WHITE_BOX),
                                              PSK_WHITE_BOX)

                    if not check_psk(device):
                        raise ValueError("Unchanged PSK")

                print("Return before driver")
                return

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
                "Invalid firmware: Abort\n" +
                warning("Please consider that removing this security "
                        "is a very bad idea!"))

    print("Abort")
