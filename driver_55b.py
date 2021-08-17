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

from goodix import (FLAGS_TRANSPORT_LAYER_SECURITY,
                    FLAGS_TRANSPORT_LAYER_SECURITY_DATA, Device,
                    check_message_pack, decode_image, encode_message_pack)
from protocol import USBProtocol

TARGET_FIRMWARE: str = "GF3268_RTSEC_APP_10041"
IAP_FIRMWARE: str = "MILAN_RTSEC_IAP_10027"
VALID_FIRMWARE: str = "GF32[0-9]{2}_RTSEC_APP_100[0-9]{2}"

PSK: bytes = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX: bytes = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH: bytes = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361")

DEVICE_CONFIG: bytes = bytes.fromhex(
    "6011607124952cc114d510e500e514f9030402000008001111ba000180ca0007"
    "008400c0b38600bbc48800baba8a00b2b28c00aaaa8e00c1c19000bbbb9200b1"
    "b1940000a8960000b6980000bf9a0000ba50000105d000000070000000720078"
    "56740034122600001220001040120003042a0102002200012024003200800001"
    "005c008000560008205800010032002c028200800cba000180ca0007002a0182"
    "03200010402200012024001400800005005c0000015600082058000300820080"
    "142a0108005c0080006200090364001800220000202a0108005c000001520008"
    "0054000001000000000000000000000000000000000000000000000000009a69")

SENSOR_WIDTH = 88
SENSOR_HEIGHT = 108


def warning(text: str) -> str:
    decorator = "#" * len(max(text.split("\n"), key=len))
    return f"\033[31;5m{decorator}\n{text}\n{decorator}\033[0m"


def check_psk(device: Device) -> bool:
    reply = device.preset_psk_read(0xbb020007)
    if not reply[0]:
        raise ValueError("Failed to read PSK")

    if reply[1] != 0xbb020007:
        raise ValueError("Invalid flags")

    return reply[2] == PMK_HASH


def write_psk(device: Device) -> bool:
    if not device.preset_psk_write(0xbb010003, PSK_WHITE_BOX):
        return False

    if not check_psk(device):
        return False

    return True


def erase_firmware(device: Device) -> None:
    device.mcu_erase_app(50, False)
    device.disconnect()


def write_firmware(device: Device,
                   offset: int,
                   payload: bytes,
                   tries: int = 2) -> None:
    for _ in range(tries):
        if device.write_firmware(offset, payload):
            return

    raise ValueError("Failed to write firmware")


def update_firmware(device: Device,
                    path: str = "firmware/55b",
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
                write_firmware(device, i, firmware[i:i + 256])

            if device.check_firmware(0, length,
                                     mkCrcFun("crc-32-mpeg")(firmware),
                                     firmware_hmac):
                device.reset(False, True, 100)
                device.disconnect()

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

    device.read_sensor_register(0x0000, 4)  # Read chip ID (0x00a1)

    device.read_otp()
    # OTP: 0x0867860a12cc02faa65d2b4b0204e20cc20c9664087bf80706000000c02d431d


def connect_device(device: Device, tls_client: socket) -> None:
    tls_client.sendall(device.request_tls_connection())

    device.protocol.write(
        encode_message_pack(tls_client.recv(1024),
                            FLAGS_TRANSPORT_LAYER_SECURITY))

    tls_client.sendall(
        check_message_pack(device.protocol.read(),
                           FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        check_message_pack(device.protocol.read(),
                           FLAGS_TRANSPORT_LAYER_SECURITY))
    tls_client.sendall(
        check_message_pack(device.protocol.read(),
                           FLAGS_TRANSPORT_LAYER_SECURITY))

    device.protocol.write(
        encode_message_pack(tls_client.recv(1024),
                            FLAGS_TRANSPORT_LAYER_SECURITY))

    sleep(0.01)  # Important otherwise an USBTimeout error occur


def get_image(device: Device, tls_client: socket, tls_server: Popen) -> None:
    if not device.upload_config_mcu(DEVICE_CONFIG):
        raise ValueError("Failed to upload config")

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x80\x12\x80\x12\x80\x98\x80\x82\x80\x12\x80\xa0\x80\x99"
        b"\x80\x7f\x80\x12\x80\x9f\x80\x93\x80\x7e", True)

    tls_client.sendall(
        device.mcu_get_image(b"\x01\x00",
                             FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

    write_pgm(decode_image(tls_server.stdout.read(14260)[:-4]), "clear-0.pgm")

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x80\x12\x80\x12\x80\x98\x80\x82\x80\x12\x80\xa0\x80\x99"
        b"\x80\x7f\x80\x12\x80\x9f\x80\x93\x80\x7e", True)

    device.mcu_switch_to_idle_mode(20)

    device.read_sensor_register(0x0082, 2)

    tls_client.sendall(
        device.mcu_get_image(b"\x01\x00",
                             FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

    write_pgm(decode_image(tls_server.stdout.read(14260)[:-4]), "clear-1.pgm")

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x80\x12\x80\x12\x80\x98\x80\x82\x80\x12\x80\xa0\x80\x99"
        b"\x80\x7f\x80\x12\x80\x9f\x80\x93\x80\x7e", True)

    if not device.switch_to_sleep_mode(0x6c):
        raise ValueError("Failed to switch to sleep mode")

    print("Waiting for finger...")

    device.mcu_switch_to_fdt_down(
        b"\x0c\x01\x80\xb0\x80\xc4\x80\xba\x80\xa6\x80\xb7\x80\xc7\x80\xc0"
        b"\x80\xaa\x80\xb4\x80\xc4\x80\xba\x80\xa6", True)

    tls_client.sendall(
        device.mcu_get_image(b"\x01\x00",
                             FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

    write_pgm(decode_image(tls_server.stdout.read(14260)[:-4]),
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
                "Don't run this program as part of a regular process."))

    code = randint(0, 9999)

    if input(f"Type {code} to continue and confirm that you are not a bot: "
            ) != str(code):
        print("Abort")
        return

    previous_firmware = None

    while True:
        device = Device(product, USBProtocol)

        device.nop()

        firmware = device.firmware_version()
        print(f"Firmware: {firmware}")

        valid_psk = check_psk(device)
        print(f"Valid PSK: {valid_psk}")

        if firmware == IAP_FIRMWARE:
            iap = IAP_FIRMWARE
        else:
            iap = device.get_iap_version(25)
        print(f"IAP: {iap}")

        if iap != IAP_FIRMWARE:
            raise ValueError(
                "Invalid IAP\n" +
                warning("Please consider that removing this security "
                        "is a very bad idea!"))

        if firmware == previous_firmware:
            raise ValueError("Unchanged firmware")

        previous_firmware = firmware

        if fullmatch(TARGET_FIRMWARE, firmware):
            if not valid_psk:
                if not write_psk(device):
                    raise ValueError("Failed to write PSK")

            run_driver(device)
            return

        if fullmatch(VALID_FIRMWARE, firmware):
            erase_firmware(device)
            continue

        if fullmatch(IAP_FIRMWARE, firmware):
            if not valid_psk:
                if not write_psk(device):
                    raise ValueError("Failed to write PSK")

            update_firmware(device)
            continue

        raise ValueError("Invalid firmware\n" +
                         warning("Please consider that removing this security "
                                 "is a very bad idea!"))
