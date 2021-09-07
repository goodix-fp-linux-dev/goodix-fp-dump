from random import randint
from re import fullmatch
from socket import socket
from struct import pack as encode
from subprocess import PIPE, STDOUT, Popen

from crcmod.predefined import mkCrcFun

from goodix import FLAGS_TRANSPORT_LAYER_SECURITY, FLAGS_MESSAGE_PROTOCOL, Device
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

DEVICE_CONFIG: bytes = (
    b"\x70\x11\x60\x71\x2c\x9d\x2c\xc9\x1c\xe5\x18\xfd\x00\xfd\x00\xfd" \
    b"\x03\xba\x00\x01\x80\xca\x00\x04\x00\x84\x00\x15\xb3\x86\x00\x00" \
    b"\xc4\x88\x00\x00\xba\x8a\x00\x00\xb2\x8c\x00\x00\xaa\x8e\x00\x00" \
    b"\xc1\x90\x00\xbb\xbb\x92\x00\xb1\xb1" \
    b"\x94\x00\x00\xa8\x96\x00\x00\xb6\x98\x00\x00\x00\x9a\x00\x00\x00" \
    b"\xd2\x00\x00\x00\xd4\x00\x00\x00\xd6\x00\x00\x00\xd8\x00\x00\x00" \
    b"\x50\x00\x01\x05\xd0\x00\x00\x00\x70\x00\x00\x00\x72\x00\x78\x56" \
    b"\x74\x00\x34\x12\x20\x00\x10\x40\x2a\x01\x02\x04\x22\x00\x01\x20" \
    b"\x24\x00\x32\x00\x80\x00\x01\x00\x5c\x00\x80\x00\x56\x00\x04\x20" \
    b"\x58\x00\x03\x02\x32\x00\x0c\x02\x66\x00\x03\x00\x7c\x00\x00\x58" \
    b"\x82\x00\x80\x15\x2a\x01\x82\x03\x22\x00\x01\x20\x24\x00\x14\x00" \
    b"\x80\x00\x01\x00\x5c\x00\x00\x01\x56\x00\x04\x20\x58\x00\x03\x02" \
    b"\x32\x00\x0c\x02\x66\x00\x03\x00\x7c\x00\x00\x58\x82\x00\x80\x1b" \
    b"\x2a\x01\x08\x00\x5c\x00\x80\x00\x54\x00\x10\x01\x62\x00\x04\x03" \
    b"\x64\x00\x19\x00\x66\x00\x03\x00\x7c\x00\x01\x58\x2a\x01\x08\x00" \
    b"\x5c\x00\x10\x01\x52\x00\x08\x00\x54\x00\x00\x01\x66\x00\x03\x00" \
    b"\x7c\x00\x01\x58\x00\x8d\x1e" )

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 88


def init_device(product: int) -> Device:
    print(len(DEVICE_CONFIG))

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

            encrypted_image = device.mcu_get_image(b"\x01\x00", FLAGS_TRANSPORT_LAYER_SECURITY)
            tls_client.sendall(encrypted_image)
            output_image = tls_server.stdout.read(10573)
            output_image = output_image[8:-5]
            write_pgm(decode_image(output_image), SENSOR_WIDTH, SENSOR_HEIGHT, "clear-0.pgm")

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
    

            encrypted_image = device.mcu_get_image(b"\x01\x00", FLAGS_TRANSPORT_LAYER_SECURITY)
            tls_client.sendall(encrypted_image)
            output_image = tls_server.stdout.read(10573)
            output_image = output_image[8:-5]
            write_pgm(decode_image(output_image), SENSOR_WIDTH, SENSOR_HEIGHT, "fingerprint.pgm")

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

            # This is needed to make the device respond to the next time that we enable it
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
