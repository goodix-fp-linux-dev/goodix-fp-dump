from random import randint
from re import fullmatch
from socket import socket
from struct import pack as encode
from subprocess import PIPE, STDOUT, Popen

from crcmod.predefined import mkCrcFun

from goodix import FLAGS_TRANSPORT_LAYER_SECURITY, Device
from protocol import USBProtocol
from tool import connect_device, decode_image, warning, write_pgm

TARGET_FIRMWARE: str = "GF_ST411SEC_APP_12109"
IAP_FIRMWARE: str = "MILAN_ST411SEC_IAP_12001"
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
    "007c0000588200801b2a0108005c008000540010016200040364001900660003"
    "007c0001582a0108005c0010015200080054000001660003007c000158008d1e")

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 88


def init_device(product: int) -> Device:
    device = Device(product, USBProtocol)

    device.nop()
    device.enable_chip(True)
    device.nop()

    return device


def check_psk(device: Device) -> bool:
    success, flags, psk = device.preset_psk_read(0xbb020003)
    if not success:
        raise ValueError("Failed to read PSK")

    if flags != 0xbb020003:
        raise ValueError("Invalid flags")

    return psk == PMK_HASH


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
    firmware_file = open(f"firmware/51x7/{TARGET_FIRMWARE}.bin", "rb")
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
        success, number = device.reset(True, False, 20)
        if not success:
            raise ValueError("Reset failed")
        if number != 2048:
            raise ValueError("Invalid reset number")

        if device.read_sensor_register(0x0000, 4) != b"\xa2\x04\x25\x00":
            raise ValueError("Invalid chip ID")

        otp = device.read_otp()
        if len(otp) < 32:
            raise ValueError("Invalid OTP")

        success, number = device.reset(True, False, 20)
        if not success:
            raise ValueError("Reset failed")
        if number != 2048:
            raise ValueError("Invalid reset number")

        if not device.upload_config_mcu(DEVICE_CONFIG):
            raise ValueError("Failed to upload config")

        if not device.set_powerdown_scan_frequency(100):
            raise ValueError("Failed to set powerdown scan frequency")

        tls_client = socket()
        tls_client.connect(("localhost", 4433))

        try:
            connect_device(device, tls_client)

            device.tls_successfully_established()

            device.nop()

            device.query_mcu_state(b"\x55", True)

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\xb2\xb2\xc2\xc2\xa7\xa7"
                b"\xb6\xb6\xa6\xa6\xb6\xb6", True
            )

            device.nav()

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x80\xb0\x80\xc0\x80\xa4"
                b"\x80\xb4\x80\xa3\x80\xb4", True
            )

            device.read_sensor_register(0x0082, 2)

            device.write_sensor_register(0x0220, b"\x78\x0b")
            device.write_sensor_register(0x0236, b"\xb9\x00")
            device.write_sensor_register(0x0238, b"\xb8\x00")
            device.write_sensor_register(0x023a, b"\xb7\x00")

            encrypted_image = device.mcu_get_image(
                b"\x01\x00",
                FLAGS_TRANSPORT_LAYER_SECURITY
            )
            tls_client.sendall(encrypted_image)
            output_image = tls_server.stdout.read(10573)
            output_image = output_image[8:-5]
            write_pgm(
                decode_image(output_image),
                SENSOR_WIDTH,
                SENSOR_HEIGHT,
                "clear-0.pgm"
            )

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x80\xb1\x80\xc1\x80\xa6"
                b"\x80\xb6\x80\xa5\x80\xb6", True
            )

            device.mcu_switch_to_fdt_down(
                b"\x0c\x01\x80\xb1\x80\xc1\x80\xa6"
                b"\x80\xb6\x80\xa5\x80\xb6", True
            )

            device.nop()

            device.query_mcu_state(b"\x55", True)

            print("Waiting for finger...")

            device.mcu_switch_to_fdt_down(
                b"\x0c\x01\x80\xb2\x80\xc2\x80\xa7"
                b"\x80\xb6\x80\xa6\x80\xb6", True
            )

            encrypted_image = device.mcu_get_image(
                b"\x01\x00",
                FLAGS_TRANSPORT_LAYER_SECURITY
            )
            tls_client.sendall(encrypted_image)
            output_image = tls_server.stdout.read(10573)
            output_image = output_image[8:-5]
            write_pgm(
                decode_image(output_image),
                SENSOR_WIDTH,
                SENSOR_HEIGHT,
                "fingerprint.pgm"
            )

            device.mcu_switch_to_fdt_up(
                b"\x0e\x01\x80\x90\x80\x9a\x80\x7b"
                b"\x80\x95\x80\x8c\x80\xa3"
            )

            tls_client.sendall(
                device.mcu_get_image(b"\x01\x00",
                                     FLAGS_TRANSPORT_LAYER_SECURITY))

            output_image = tls_server.stdout.read(10573)
            output_image = output_image[8:-5]
            write_pgm(decode_image(output_image),
                      SENSOR_WIDTH, SENSOR_HEIGHT, "clear-1.pgm")

            device.nav()

            # Required after capture to keep device responding
            device.mcu_switch_to_fdt_down(
                b"\x0c\x01\x80\xa7\x80\xb9\x80\xa3"
                b"\x80\xb5\x80\xa4\x80\xb6", False
            )
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
