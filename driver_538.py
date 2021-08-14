from hashlib import sha256
from hmac import new as hmac
from random import randint
from re import fullmatch
from socket import socket
from struct import pack as encode
from subprocess import PIPE, STDOUT, Popen
from time import sleep
from typing import List

from goodix import (FLAGS_TRANSPORT_LAYER_SECURITY, Device,
                    FLAGS_TRANSPORT_LAYER_SECURITY_DATA, check_message_pack,
                    decode_image, encode_message_pack)
from protocol import USBProtocol

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
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")

DEVICE_CONFIG: bytes = bytes.fromhex(
    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca0008008400bec38600b1"
    "b68800baba8a00b3b38c00bcbc8e00b1b19000bbbb9200b1b194000000960000"
    "00980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c000101560024205800010232000402660000027c00005882007f082a0182"
    "072200012024001400800001405c00e700560006145800040232000c02660000"
    "027c000058820080082a0108005c000101540000016200080464001000660000"
    "027c0000582a0108005c00dc005200080054000001660000027c00005820c51d")

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 88


def warning(text: str) -> str:
    decorator = "#" * len(max(text.split("\n"), key=len))
    return f"\033[31;5m{decorator}\n{text}\n{decorator}\033[0m"


def check_psk(device: Device, tries: int = 2) -> bool:
    for _ in range(tries):
        reply = device.preset_psk_read(0xbb020001, len(PMK_HASH), 0)
        if not reply[0]:
            raise ValueError("Failed to read PSK")

        if reply[1] != 0xbb020001:
            raise ValueError("Invalid flags")

        if reply[2] == PMK_HASH:
            return True

    return False


def erase_firmware(device: Device) -> None:
    device.mcu_erase_app(50)


def write_firmware(device: Device,
                   offset: int,
                   payload: bytes,
                   number: int,
                   tries: int = 2) -> None:
    for _ in range(tries):
        if device.write_firmware(offset, payload, number):
            return

    raise ValueError("Failed to write firmware")


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
                write_firmware(device, i, firmware[i:i + 256], 2)

            if device.check_firmware(None, None, None, firmware_hmac):
                device.reset(False, True, 50)
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

    device.read_sensor_register(0x0000, 4)  # Read chip ID (0x00a6)

    device.read_otp()
    # OTP: 0x4e4e53304b2e0000517681a4aa89e409085c5c96800000f0a06ca56ea0a0746ce7280400980052f0072228249fa5a10000000000000000000000000009ff0000


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
        b"\x0d\x01\x28\x01\x22\x01\x28\x01\x24\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        False)
    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x28\x01\x22\x01\x28\x01\x24\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        True)

    device.write_sensor_register(0x022c, b"\x0a\x03")

    tls_client.sendall(
        device.mcu_get_image(FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

    data_file = open("data.bin", "wb")
    data_file.write(tls_server.stdout.read(7684))
    data_file.close()

    print("Return early")
    return

    write_pgm(decode_image(tls_server.stdout.read(7684)[:-4]), "clear-0.pgm")

    return

    device.mcu_switch_to_fdt_mode(
        b"\x0d\x01\x80\xaf\x80\xbf\x80\xa4\x80\xb8\x80\xa8\x80\xb7")

    print("Waiting for finger...")

    device.mcu_switch_to_fdt_down(
        b"\x0c\x01\x80\xaf\x80\xbf\x80\xa4\x80\xb8\x80\xa8\x80\xb7")

    tls_client.sendall(device.mcu_get_image(FLAGS_TRANSPORT_LAYER_SECURITY))

    write_pgm(decode_image(tls_server.stdout.read(7684)[8:-5]),
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

        device = Device(product, USBProtocol)

        device.nop()

        while True:

            device.empty_buffer()

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
                    continue

                run_driver(device)
                return

            if fullmatch(VALID_FIRMWARE, firmware):
                erase_firmware(device)
                continue

            if fullmatch(IAP_FIRMWARE, firmware):
                if not valid_psk:
                    device.preset_psk_write(
                        0xbb010003, PSK_WHITE_BOX, 114, 0,
                        bytes.fromhex("56a5bb956b7c8d9e0000"))

                    if not check_psk(device):
                        raise ValueError("Unchanged PSK")

                update_firmware(device)

                device = Device(product, USBProtocol)

                device.nop()

                continue

            raise ValueError(
                "Invalid firmware\n" +
                warning("Please consider that removing this security "
                        "is a very bad idea!"))
