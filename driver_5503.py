import hashlib
import hmac
import random
import re
import socket
import struct
import subprocess
from time import sleep

import crcmod

import goodix
import protocol
import tool

WORKING_FIRMWARE = "GF32[0,5]8_RTSEC_APP_10062"
TARGET_FIRMWARE = "GF3208_RTSEC_APP_10062"
IAP_FIRMWARE = "MILAN_RTSEC_IAP_10027"
VALID_FIRMWARE = "GF32[0-9]{2}_RTSEC_APP_100[0-9]{2}"

PSK = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000")

PSK_WHITE_BOX = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5")

PMK_HASH = bytes.fromhex(
    "81b8ff490612022a121a9449ee3aad2792f32b9f3141182cd01019945ee50361")

DEVICE_CONFIG = bytes.fromhex(
    "581160712c9d2cc91ce518fd00fd00fd03ba000180ca0004008400c0b38600bb"
    "c48800baba8a00b2b28c00aaaa8e00c1c19000bbbb9200b1b1940000a8960000"
    "b6980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c008000560024205800030032000c02660000027c000058820080152a0182"
    "032200012024001400800001005c000001560004205800030032000c02660000"
    "027c000058820080162a0108005c000001540000016200080464001000660000"
    "027c0000582a0108005c0000015200080054000001660000027c00005800a474"
)

SENSOR_WIDTH = 80
SENSOR_HEIGHT = 64

def init_device(product: int):
    device = goodix.Device(product, protocol.USBProtocol)

    device.nop()

    return device


def check_psk(device: goodix.Device):
    reply = device.preset_psk_read(0xbb020007)
    if not reply[0]:
        raise ValueError("Failed to read PSK")

    if reply[1] != 0xbb020007:
        raise ValueError("Invalid flags")

    return reply[2] == PMK_HASH


def write_psk(device: goodix.Device):
    if not device.preset_psk_write(0xbb010003, PSK_WHITE_BOX):
        return False

    if not check_psk(device):
        return False

    return True


def erase_firmware(device: goodix.Device):
    device.mcu_erase_app(50, False)
    device.disconnect()


def update_firmware(device: goodix.Device):
    firmware_file = open(f"firmware/5503/{TARGET_FIRMWARE}.bin", "rb")
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
            if not device.write_firmware(i, firmware[i:i + 256]):
                raise ValueError("Failed to write firmware")

        if not device.check_firmware(
                0, length,
                crcmod.predefined.mkCrcFun("crc-32-mpeg")(firmware),
                firmware_hmac):
            raise ValueError("Failed to check firmware")

    except Exception as error:
        print(
            tool.warning(
                f"The program went into serious problems while trying to "
                f"update the firmware: {error}"))

        erase_firmware(device)

        raise error

    device.reset(False, True, 100)
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

        device.read_sensor_register(0000, 4)  # Read chip ID (0x00a1)

        device.nop()

        device.read_otp()

        device.pov_image_check()

        tls_client = socket.socket()
        tls_client.connect(("localhost", 4433))

        try:
            tool.connect_device(device, tls_client)

            if not device.upload_config_mcu(DEVICE_CONFIG):
                raise ValueError("Failed to upload config")

            device.set_drv_state()
            device.set_drv_state() # The windows driver does this twice

            device.mcu_get_pov_image()

            device.mcu_switch_to_fdt_mode(
                bytes.fromhex("0d018b0084008c0088008096809180928085808c8086"),
                True
            )

            tls_client.sendall(
                device.mcu_get_image(
                    bytes.fromhex("01008b0084008c008800"),
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:]
            )

            tls_server.stdout.flush()

            clear_0_image = tool.decode_image(tls_server.stdout.read(7684)[:-4])
            tool.write_pgm(
                clear_0_image,
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-0.pgm"
            )

            tls_server.stdout.flush()

            device.mcu_switch_to_fdt_mode(
                bytes.fromhex("0d018b0084008c0088008096809180928085808c8086"),
                True
            )

            device.mcu_switch_to_idle_mode(20)

            device.read_sensor_register(0x0082, 2)

            tls_client.sendall(
                device.mcu_get_image(
                    bytes.fromhex("01008b0084008c008800"),
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:]
            )

            tls_server.stdout.flush()

            clear_1_image = tool.decode_image(tls_server.stdout.read(7684)[:-4])
            tool.write_pgm(
                clear_1_image,
                SENSOR_WIDTH, SENSOR_HEIGHT, "clear-1.pgm"
            )

            tls_server.stdout.flush()

            # Reset scanner
            device.mcu_switch_to_fdt_mode(
                bytes.fromhex("0d018b0084008c0088008096809180928085808c8086"),
                True
            )

            # Set PC state?? cmd:000f80b980ae80b980af80b580aa00000000000000000000000016068b0084008c0088000a020a03
            # Maybe this is required. Idk. Windows driver sends it.

            device.nop()

            device.query_mcu_state(
                bytes.fromhex("000132"), # 010032
                True
            )

            device.pov_image_check()

            device.mcu_switch_to_fdt_down(
                bytes.fromhex("0c018b0084008c00880080b980ae80b980af80b580aa"),
                False
            )

            print("Please place your finger on the sensor")

            device.mcu_switch_to_fdt_down(
                bytes.fromhex("0c018b0084008c00880080b980ae80b980af80b580aa"),
                True
            )

            tls_server.stdout.flush()

            tls_client.sendall(
                device.mcu_get_image(
                    bytes.fromhex("01008b0084008c008800"),
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)[9:]
            )

            tls_server.stdout.flush()
            sleep(0.1)

            fingerprint_image = tool.decode_image(tls_server.stdout.read(7684)[:-4])
            tool.write_pgm(
                fingerprint_image,
                SENSOR_WIDTH, SENSOR_HEIGHT, "fingerprint-0.pgm"
            )

            tls_server.stdout.flush()

            # Finger scanned, reset sensor
            device.mcu_switch_to_fdt_mode(
                bytes.fromhex("0d018b0084008c00880080b980ae80b980af80b580aa"),
                True
            )

            print("Please remove your finger from the sensor")

            device.mcu_switch_to_fdt_up(
                bytes.fromhex("0e018b0084008c008800809580898099808a808d808d")
            )

            device.mcu_switch_to_fdt_up(
                bytes.fromhex("0e018b0084008c008800809b808e80a28090809f80a8")
            )

            device.mcu_switch_to_fdt_down(
                bytes.fromhex("0c018b0084008c00880080ba80af80ba80b080b680ab"),
                False
            )

            device.query_mcu_state(
                bytes.fromhex("010032"),
                True
            )

        finally:
            tls_client.close()
    finally:
        tls_server.terminate()


def main(product: int):
    # print(
    #     tool.warning(
    #         "This program might break your device.\n"
    #         "Consider that it may flash the device firmware.\n"
    #         "Continue at your own risk.\n"
    #         "But don't hold us responsible if your device is broken!\n"
    #         "Don't run this program as part of a regular process."))

    # code = random.randint(0, 9999)

    # if input(f"Type {code} to continue and confirm that you are not a bot: "
    #          ) != str(code):
    #     print("Abort")
    #     return

    previous_firmware = None

    device = init_device(product)

    while True:
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
                tool.warning("Please consider that removing this security "
                             "is a very bad idea!"))

        if firmware == previous_firmware:
            raise ValueError("Unchanged firmware")

        previous_firmware = firmware

        if re.fullmatch(WORKING_FIRMWARE, firmware):
            if not valid_psk:
                if not write_psk(device):
                    raise ValueError("Failed to write PSK")

            run_driver(device)
            return

        if re.fullmatch(VALID_FIRMWARE, firmware):
            erase_firmware(device)

            device = init_device(product)

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
