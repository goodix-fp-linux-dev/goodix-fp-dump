import hashlib
import hmac
import random
import re
import socket
import struct
import subprocess

import goodix
import protocol
import tool

TARGET_FIRMWARE = "GFUSB_GM168SEC_APP_10019"
IAP_FIRMWARE = "MILAN_GM168SEC_IAP_10007"
VALID_FIRMWARE = "GFUSB_GM168SEC_APP_100[0-9]{2}"

PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH = bytes.fromhex(
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925")

DEVICE_CONFIG = bytes.fromhex(
    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca0008008400bec38600b1"
    "b68800baba8a00b3b38c00bcbc8e00b1b19000bbbb9200b1b194000000960000"
    "00980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c000101560024205800010232000402660000027c00005882007f082a0182"
    "072200012024001400800001405c00ea00560006145800040232000c02660000"
    "027c000058820080082a0108005c000101540000016200080464001000660000"
    "027c0000582a0108005c00e8005200080054000001660000027c00005820c50e")

DEVICE_POV_CONFIG = bytes.fromhex(
    "040f8d8d868697978f8f9b9b929296968c8c00000000000000000803a700a100"
    "a700a3000a020503")

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 64


def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)

    device.nop()

    return device


def check_psk(device: goodix.Device):
    reply = device.preset_psk_read(0xbb020001, len(PMK_HASH), 0)
    if not reply[0]:
        raise ValueError("Failed to read PSK")

    if reply[1] != 0xbb020001:
        raise ValueError("Invalid flags")

    return reply[2] == PMK_HASH


def write_psk(device: goodix.Device):
    if not device.preset_psk_write(0xbb010003, PSK_WHITE_BOX, 114, 0,
                                   bytes.fromhex("56a5bb956b7c8d9e0000")):
        return False

    if not check_psk(device):
        return False

    return True


def erase_firmware(device: goodix.Device):
    device.mcu_erase_app(50, True)


def update_firmware(device: goodix.Device):
    firmware_file = open(f"firmware/52xd/{TARGET_FIRMWARE}.bin", "rb")
    firmware = firmware_file.read()
    firmware_file.close()

    mod = b""
    for i in range(1, 65):
        mod += struct.pack("<B", i)
    raw_pmk = (struct.pack(">H", len(PSK)) + PSK) * 2
    pmk = hashlib.sha256(raw_pmk).digest()
    pmk_hmac = hmac.new(pmk, mod, hashlib.sha256).digest()
    firmware_hmac = hmac.new(pmk_hmac, firmware, hashlib.sha256).digest()

    try:
        length = len(firmware)
        for i in range(0, length, 256):
            if not device.write_firmware(i, firmware[i:i + 256], 2):
                raise ValueError("Failed to write firmware")

        if not device.check_firmware(None, None, None, firmware_hmac):
            raise ValueError("Failed to check firmware")

    except Exception as error:
        print(
            tool.warning(
                f"The program went into serious problems while trying to "
                f"update the firmware: {error}"))

        erase_firmware(device)

        raise error

    device.reset(False, True, 50)
    device.disconnect()


def run_driver(device: goodix.Device):
    tls_server = subprocess.Popen([
        "openssl", "s_server", "-nocert", "-psk",
        PSK.hex(), "-port", "4433", "-quiet"
    ],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)

    try:
        if not device.reset(True, False, 20)[0]:
            raise ValueError("Reset failed")

        device.read_sensor_register(0x0000,
                                    4)  # Read chip ID (0x00a5 or 0x00a6)

        otp = device.read_otp()

        if len(otp) < 64:
            raise ValueError("Invalid OTP")

        # OTP 1: 4e4c4d31372e0000b9828da2a2d73e09
        #        08196896800000ee6014a774a060b614
        #        ea2704009b0056f007212723a1a7a300
        #        00000000000000000000000083760000
        # OTP 2: 4e4b35594c2e00002983759520190009
        #        08274c96800000f0103cae6ea010593c
        #        ea2f04009c0053f00729312ba8b0aa00
        #        000000000000000000000000f3830000

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))

        try:
            tool.connect_device(device, tls_client)

            if not device.upload_config_mcu(DEVICE_CONFIG):
                raise ValueError("Failed to upload config")

            device.set_drv_state()

            device.mcu_get_pov_image()

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00", False)
            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x01", True)

            device.write_sensor_register(0x022c, b"\x0a\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x01\x03\x27\x01\x21\x01\x27\x01\x23\x01",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-0.pgm")

            device.write_sensor_register(0x022c, b"\x0a\x02")

            device.write_sensor_register(0x022c, b"\x0a\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x81\x03\x27\x01\x21\x01\x27\x01\x23\x01",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-1.pgm")

            device.write_sensor_register(0x022c, b"\x0a\x02")

            device.write_sensor_register(0x022c, b"\x0a\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x81\x03\x18\x01\x12\x01\x18\x01\x14\x01",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-2.pgm")

            device.write_sensor_register(0x022c, b"\x0a\x02")

            device.mcu_switch_to_fdt_mode(
                b"\x8d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00", False)
            device.mcu_switch_to_fdt_mode(
                b"\x8d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x01", True)

            device.write_sensor_register(0x022c, b"\x0a\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x81\x03\x27\x01\x21\x01\x27\x01\x23\x01",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-3.pgm")

            device.write_sensor_register(0x022c, b"\x0a\x02")

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00", False)
            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x01", True)

            device.set_pov_config(DEVICE_POV_CONFIG)

            device.mcu_switch_to_sleep_mode()

            device.query_mcu_state(b"\x01\x01\x01", False)

            device.mcu_switch_to_fdt_down(
                b"\x9c\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
                b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
                b"\x8c\x8c\x00\x00\x05\x03\xa7\x00"
                b"\xa1\x00\xa7\x00\xa3\x00\x00", False)

            device.mcu_switch_to_fdt_down(
                b"\x9c\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
                b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
                b"\x8c\x8c\x01\x00\x05\x03\xa7\x00"
                b"\xa1\x00\xa7\x00\xa3\x00\x00", False)

            device.mcu_switch_to_sleep_mode()

            device.query_mcu_state(b"\x00\x00\x00", False)

            device.query_mcu_state(b"\x01\x01\x01", False)

            device.mcu_switch_to_fdt_down(
                b"\x9c\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
                b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
                b"\x8c\x8c\x00\x00\x05\x03\xa7\x00"
                b"\xa1\x00\xa7\x00\xa3\x00\x00", False)

            print("Waiting for finger...")

            device.mcu_switch_to_fdt_down(
                b"\x9c\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
                b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
                b"\x8c\x8c\x01\x00\x05\x03\xa7\x00"
                b"\xa1\x00\xa7\x00\xa3\x00\x00", True)

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
                b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
                b"\x8c\x8c\x00", False)

            device.mcu_switch_to_fdt_mode(
                b"\x0d\x01\x27\x01\x21\x01\x27\x01"
                b"\x23\x01\x8d\x8d\x86\x86\x97\x97"
                b"\x8f\x8f\x9b\x9b\x92\x92\x96\x96"
                b"\x8c\x8c\x01", True)

            device.write_sensor_register(0x022c, b"\x05\x03")

            tls_client.sendall(
                device.mcu_get_image(
                    b"\x45\x03\xa7\x00\xa1\x00\xa7\x00\xa3\x00",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:])

            tool.write_pgm(
                tool.decode_image(tls_server.stdout.read(7684)[:-4]),
                SENSOR_WIDTH, SENSOR_HEIGHT, "fingerprint.pgm")

        finally:
            tls_client.close()
    finally:
        tls_server.terminate()


def main(product: int):
    print(
        tool.warning(
            "This program might break your device.\n"
            "Consider that it may flash the device firmware.\n"
            "Continue at your own risk.\n"
            "But don't hold us responsible if your device is broken!\n"
            "Don't run this program as part of a regular process."))

    code = random.randint(0, 9999)

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

        if re.fullmatch(TARGET_FIRMWARE, firmware):
            if not valid_psk:
                erase_firmware(device)
                continue

            run_driver(device)
            return

        if re.fullmatch(VALID_FIRMWARE, firmware):
            erase_firmware(device)
            continue

        if re.fullmatch(IAP_FIRMWARE, firmware):
            if not valid_psk:
                if not write_psk(device):
                    raise ValueError("Failed to write PSK")

            update_firmware(device)

            device = init_device(product)

            continue

        raise ValueError(
            "Invalid firmware\n" +
            tool.warning("Please consider that removing this security "
                         "is a very bad idea!"))
