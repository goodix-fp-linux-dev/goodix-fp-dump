from random import randint
from re import fullmatch
from socket import socket
from struct import pack as encode
from subprocess import PIPE, STDOUT, Popen

from crcmod.predefined import mkCrcFun

from goodix import FLAGS_TRANSPORT_LAYER_SECURITY, Device
from protocol import USBProtocol, SPIProtocol
from tool import connect_device, decode_image, warning, write_pgm

TARGET_FIRMWARE: str = "GF_ST411SEC_APP_12117"
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
    device = Device(product, SPIProtocol)

    #device.nop()
    #device.enable_chip(True)
    #device.nop()

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
    firmware_file = open(f"firmware/51x0/{TARGET_FIRMWARE}.bin", "rb")
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
        if len(otp) < 64:
            raise ValueError("Invalid OTP")

        # OTP 0 = 5332383733342e0032778aa2d495ca05
        #         5107050a7d0bfd274103110cf17f800c
        #         38813034a57f5ef406c4bd4201bdb7b9
        #         b7b7b7b9b7b73230a55a5ea1850cfd71
        # OTP 1 = 5332423937332e000a777aa3452cec02
        #         510705027d4bd5274103d10cf18f700c
        #         38c13033a58f5ff407f48e71018eb6b7
        #         b6b6b6b7b6b63450a55a5fa0c814d548

        # OTP[00] = CP_DATA[00] = 0x53
        # OTP[01] = CP_DATA[01] = 0x32
        # OTP[02] = CP_DATA[02] = 0x38
        # OTP[03] = CP_DATA[03] = 0x37
        # OTP[04] = CP_DATA[04] = 0x33
        # OTP[05] = CP_DATA[05] = 0x34
        # OTP[06] = CP_DATA[06] = 0x2e
        # OTP[07] = CP_DATA[07] = 0x00
        # OTP[08] = CP_DATA[08] = 0x32
        # OTP[09] = CP_DATA[09] = 0x77
        # OTP[10] = CP_DATA[10] = 0x8a
        # OTP[11] = FT_DATA[00] = 0xa2
        # OTP[12] = FT_DATA[01] = 0xd4
        # OTP[13] = FT_DATA[02] = 0x95
        # OTP[14] = FT_DATA[03] = 0xca
        # OTP[15] = FT_DATA[04] = 0x05
        # OTP[16] = FT_DATA[05] = 0x51
        # OTP[17] = FT_DATA[06] = 0x07
        # OTP[18] = FT_DATA[07] = 0x05
        # OTP[19] = FT_DATA[08] = 0x0a
        # OTP[20] = MT_DATA[00] = 0x7d
        # OTP[21] = MT_DATA[01] = 0x0b
        # OTP[22] = MT_DATA[02] = ~CRC_8_CHECKSUM(MT_DAC_DATA) & 0xff = 0xfd
        # OTP[23] = MT_DATA[03] = 0x27
        # OTP[24] = MT_DATA[04] = 0x41
        # OTP[25] = MT_DATA[05] = 0x03
        # OTP[26] = MT_DATA[06] = 0x11
        # OTP[27] = MT_DATA[07] = FDT_OFFSET = 0x0c
        # OTP[28] = FT_DATA[09] = 0xf1
        # OTP[29] = MT_DATA[08] = 0x7f
        # OTP[30] = MT_DATA[09] = 0x80
        # OTP[31] = MT_DATA[10] = 0x0c
        # OTP[32] = MT_DATA[11] = 0x38
        # OTP[33] = MT_DATA[12] = 0x81
        # OTP[34] = MT_DATA[13] = 0x30
        # OTP[35] = MT_DATA[14] = 0x34
        # OTP[36] = CP_DATA[11] = 0xa5
        # OTP[37] = CP_DATA[12] = 0x7f
        # OTP[38] = CP_DATA[13] = 0x5e
        # OTP[39] = CP_DATA[14] = 0xf4
        # OTP[40] = MT_DATA[15] = 0x06
        # OTP[41] = MT_DATA[16] = 0xc4
        # OTP[42] = MT_DATA[17] = TCODE << 4 | DELTA & 0Xf = 0xbd
        # OTP[43] = MT_DATA[18] = THRESHHOLD = 0x42
        # OTP[44] = MT_DATA[19] = 0x01
        # OTP[45] = MT_DATA[20] = 0xbd
        # OTP[46] = MT_DATA[21] = MT_DAC_DATA[0] = 0xb7
        # OTP[47] = MT_DATA[22] = MT_DAC_DATA[1] = 0xb9
        # OTP[48] = MT_DATA[23] = MT_DAC_DATA[2] = 0xb7
        # OTP[49] = MT_DATA[24] = MT_DAC_DATA[3] = 0xb7
        # OTP[50] = FT_DATA[10] = FT_DAC_DATA[0] = 0xb7
        # OTP[51] = FT_DATA[11] = FT_DAC_DATA[1] = 0xb9
        # OTP[52] = FT_DATA[12] = FT_DAC_DATA[2] = 0xb7
        # OTP[53] = FT_DATA[13] = FT_DAC_DATA[3] = 0xb7
        # OTP[54] = MT_DATA[25] = 0x32
        # OTP[55] = MT_DATA[26] = 0x30
        # OTP[56] = FT_DATA[14] = 0xa5
        # OTP[57] = FT_DATA[15] = 0x5a
        # OTP[58] = FT_DATA[16] = 0x5e
        # OTP[59] = FT_DATA[17] = 0xa1
        # OTP[60] = ~CRC_8_CHECKSUM(CP_DATA) & 0xff = 0x85
        # OTP[61] = ~CRC_8_CHECKSUM(FT_DATA) & 0xff = 0x0c
        # OTP[62] = FT_DATA[18] = ~CRC_8_CHECKSUM(FT_DAC_DATA) & 0xff = 0xfd
        # OTP[63] = ~CRC_8_CHECKSUM(MT_DATA) & 0xff = 0x71

        if ~mkCrcFun("crc-8")(otp[0:11] + otp[36:40]) & 0xff != otp[60]:
            raise ValueError("Invalid OTP CP data checksum")

        if ~mkCrcFun("crc-8")(otp[20:28] + otp[29:36] + otp[40:50] +
                              otp[54:56]) & 0xff != otp[63]:
            raise ValueError("Invalid OTP MT data checksum")

        if ~mkCrcFun("crc-8")(otp[11:20] + otp[28:29] + otp[50:54] +
                              otp[56:60] + otp[62:63]) & 0xff != otp[61]:
            raise ValueError("Invalid OTP FT data checksum")

        if ~mkCrcFun("crc-8")(otp[50:54]) & 0xff != otp[62]:
            raise ValueError("Invalid OTP DAC FT data checksum")

        if ~mkCrcFun("crc-8")(otp[46:50]) & 0xff != otp[22]:
            raise ValueError("Invalid OTP DAC MT data checksum")

        if otp[50:54] != otp[46:50]:
            raise ValueError("Invalid OTP DAC data")

        if otp[42] == 0x00 or otp[42] != ~otp[43] & 0xff:
            if otp[43] == 0x00 or otp[43] != ~otp[43] & 0xff:
                if otp[42] == 0x00 or otp[43] != otp[42]:
                    raise ValueError("Invalid OTP Tcode and threshold data")

        tcode = ((otp[42] >> 4) + 1) * 16 + 64
        delta = int(((otp[42] & 0xf) + 2) * 25600 / tcode / 3) >> 4 & 0xff

        if otp[27] != 0x00:
            if otp[27] & 3 == otp[27] >> 4 & 3:
                fdt_offset = otp[27] & 3
            elif otp[27] & 3 == otp[27] >> 2 & 3:
                fdt_offset = otp[27] & 3
            elif otp[27] >> 4 & 3 == otp[27] >> 2 & 3:
                fdt_offset = otp[27] >> 4 & 3
            else:
                fdt_offset = 0
        else:
            fdt_offset = 0

        success, number = device.reset(True, False, 20)
        if not success:
            raise ValueError("Reset failed")
        if number != 2048:
            raise ValueError("Invalid reset number")

        device.mcu_switch_to_idle_mode(20)

        device.write_sensor_register(0x0220, encode("<H", otp[46] << 4 | 8))
        device.write_sensor_register(0x0236, encode("<H", otp[47]))
        device.write_sensor_register(0x0238, encode("<H", otp[48]))
        device.write_sensor_register(0x023a, encode("<H", otp[49]))

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

            device.nav()

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
