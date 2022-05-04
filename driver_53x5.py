import logging
import os
import time
from dataclasses import dataclass
from typing import Optional
import re

from wrapless import Device, decode_u32, FingerDetectionOperation
from protocol import USBProtocol
from tool import decode_image, write_pgm

from Crypto.Hash import SHA256

VALID_FIRMWARE: str = r"GF5288_HTSEC_APP_100(11|20)"

PSK: bytes = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
)

PSK_WHITE_BOX: bytes = bytes.fromhex(
    "ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b"
    "6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e"
    "60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5"
)

SENSOR_WIDTH = 108
SENSOR_HEIGHT = 88


def is_valid_psk(device: Device) -> bool:
    psk_hash = device.read_psk_hash()
    return psk_hash == SHA256.SHA256Hash(PSK).digest()


def write_psk(device: Device):
    print(f"Writing white-box all-zero PSK")
    device.write_psk_white_box(PSK_WHITE_BOX)

    if not is_valid_psk(device):
        raise Exception("Could not set all-zero PSK")


def device_enable(device: Device):
    device.reset(0, False)
    time.sleep(0.01)

    reg_data = device.read_data(0, 4, 0.2)
    chip_id = decode_u32(reg_data)
    if chip_id >> 8 == 0x220C:
        sensor_type = 9
    else:
        raise Exception(f"Unsupported chip ID: {chip_id}")

    print(f"Chip ID: {chip_id:#x}")
    print(f"Sensor type: {sensor_type}")


OTP_HASH_TABLE = bytes.fromhex(
    "00 07 0e 09 1c 1b 12 15 38 3f 36 31 24 23 2a 2d"
    "70 77 7e 79 6c 6b 62 65 48 4f 46 41 54 53 5a 5d"
    "e0 e7 ee e9 fc fb f2 f5 d8 df d6 d1 c4 c3 ca cd"
    "90 97 9e 99 8c 8b 82 85 a8 af a6 a1 b4 b3 ba bd"
    "c7 c0 c9 ce db dc d5 d2 ff f8 f1 f6 e3 e4 ed ea"
    "b7 b0 b9 be ab ac a5 a2 8f 88 81 86 93 94 9d 9a"
    "27 20 29 2e 3b 3c 35 32 1f 18 11 16 03 04 0d 0a"
    "57 50 59 5e 4b 4c 45 42 6f 68 61 66 73 74 7d 7a"
    "89 8e 87 80 95 92 9b 9c b1 b6 bf b8 ad aa a3 a4"
    "f9 fe f7 f0 e5 e2 eb ec c1 c6 cf c8 dd da d3 d4"
    "69 6e 67 60 75 72 7b 7c 51 56 5f 58 4d 4a 43 44"
    "19 1e 17 10 05 02 0b 0c 21 26 2f 28 3d 3a 33 34"
    "4e 49 40 47 52 55 5c 5b 76 71 78 7f 6a 6d 64 63"
    "3e 39 30 37 22 25 2c 2b 06 01 08 0f 1a 1d 14 13"
    "ae a9 a0 a7 b2 b5 bc bb 96 91 98 9f 8a 8d 84 83"
    "de d9 d0 d7 c2 c5 cc cb e6 e1 e8 ef fa fd f4 f3"
)


def compute_otp_hash(data):
    checksum = 0
    for byte in data:
        checksum = OTP_HASH_TABLE[checksum ^ byte]
    return ~checksum & 0xFF


def verify_otp_hash(otp):
    data = otp[:25] + otp[26:]
    received_hash = otp[25]
    computed_hash = compute_otp_hash(data)

    if received_hash == computed_hash:
        print("Valid OTP")
    else:
        raise Exception(f"OTP hash incorrect: {received_hash} != {computed_hash}")


FDT_BASE_LEN = 24


@dataclass
class CalibrationParams:
    tcode: int

    delta_fdt: int
    delta_down: int
    delta_up: int
    delta_img: int
    delta_nav: int

    dac_h: int
    dac_l: int

    dac_delta: int

    fdt_base_down: bytes
    fdt_base_up: bytes
    fdt_base_manual: bytes

    calib_image: Optional[list[int]]

    def update_fdt_bases(self, fdt_base: bytes):
        assert len(fdt_base) == FDT_BASE_LEN
        self.fdt_base_down = fdt_base[:]
        self.fdt_base_up = fdt_base[:]
        self.fdt_base_manual = fdt_base[:]


def check_sensor(device: Device):
    otp = device.read_otp(0.2)
    print(f"OTP: {otp.hex(' ')}")

    verify_otp_hash(otp)

    diff = otp[17] >> 1 & 0x1F
    print(f"[0x11]:{otp[0x11]:#x}, diff[5:1]={diff:#x}")

    tcode = otp[23] + 1 if otp[23] != 0 else 0

    if diff == 0:
        delta_fdt = 0  # uninit?
        delta_down = 0xD
        delta_up = 0xB
        delta_img = 0xC8
        delta_nav = 0x28
    else:
        tmp = diff + 5
        tmp2 = (tmp * 0x32) >> 4

        delta_fdt = tmp2 // 5
        delta_down = tmp2 // 3
        delta_up = delta_down - 2
        delta_img = 0xC8
        delta_nav = tmp * 4

    if otp[17] == 0 or otp[22] == 0 or otp[31] == 0:
        dac_h = 0x97
        dac_l = 0xD0
    else:
        # dac_h = otp[17][0] | otp[22]
        dac_h = (otp[17] << 8 ^ otp[22]) & 0x1FF
        # dac_l = otp[17][6] | otp[31]
        dac_l = (otp[17] & 0x40) << 2 ^ otp[31]

    print(
        f"tcode:{hex(tcode)} delta down:{hex(delta_down)} "
        f"delta up:{hex(delta_up)} delta img:{hex(delta_img)} "
        f"delta nav:{hex(delta_nav)} dac_h:{hex(dac_h)} dac_l:{hex(dac_l)}"
    )

    dac_delta = 0xC83 // tcode
    print(f"sensor broken dac_delta={dac_delta}")

    fdt_base = b"\x00" * FDT_BASE_LEN
    return CalibrationParams(
        tcode,
        delta_fdt,
        delta_down,
        delta_up,
        delta_img,
        delta_nav,
        dac_h,
        dac_l,
        dac_delta,
        fdt_base[:],
        fdt_base[:],
        fdt_base[:],
        None,
    )


DEFAULT_CONFIG = bytes.fromhex(
    "40 11 6c 7d 28 a5 28 cd 1c e9 10 f9 00 f9 00 f9"
    "00 04 02 00 00 08 00 11 11 ba 00 01 80 ca 00 07"
    "00 84 00 be b2 86 00 c5 b9 88 00 b5 ad 8a 00 9d"
    "95 8c 00 00 be 8e 00 00 c5 90 00 00 b5 92 00 00"
    "9d 94 00 00 af 96 00 00 bf 98 00 00 b6 9a 00 00"
    "a7 30 00 6c 1c 50 00 01 05 d0 00 00 00 70 00 00"
    "00 72 00 78 56 74 00 34 12 26 00 00 12 20 00 10"
    "40 12 00 03 04 02 02 16 21 2c 02 0a 03 2a 01 02"
    "00 22 00 01 20 24 00 32 00 80 00 05 04 5c 00 00"
    "01 56 00 28 20 58 00 01 00 32 00 24 02 82 00 80"
    "0c 20 02 88 0d 2a 01 92 07 22 00 01 20 24 00 14"
    "00 80 00 05 04 5c 00 00 01 56 00 08 20 58 00 03"
    "00 32 00 08 04 82 00 80 0c 20 02 88 0d 2a 01 18"
    "04 5c 00 80 00 54 00 00 01 62 00 09 03 64 00 18"
    "00 82 00 80 0c 20 02 88 0d 2a 01 18 04 5c 00 80"
    "00 52 00 08 00 54 00 00 01 00 00 00 00 00 61 4f"
)


def fix_config_checksum(config):
    checksum = 0xA5A5
    for short_idx in range(0, len(config) - 2, 2):
        short = int.from_bytes(config[short_idx : short_idx + 2], byteorder="little")
        checksum += short
        checksum &= 0xFFFF
    checksum = 0x10000 - checksum
    checksum_bytes = checksum.to_bytes(length=2, byteorder="little")

    config[-2] = checksum_bytes[0]
    config[-1] = checksum_bytes[1]


TCODE_TAG = 0x5C
DAC_L_TAG = 0x220
DELTA_DOWN_TAG = 0x82


def replace_value_in_section(config, section_num, tag, value):
    value_bytes = int.to_bytes(value, length=2, byteorder="little")

    section_table = config[1:0x11]
    section_base = section_table[section_num * 2]
    section_size = section_table[section_num * 2 + 1]

    for entry_base in range(section_base, section_base + section_size, 4):
        entry_tag = int.from_bytes(
            config[entry_base : entry_base + 2], byteorder="little"
        )
        if entry_tag == tag:
            config[entry_base + 2] = value_bytes[0]
            config[entry_base + 3] = value_bytes[1]


def upload_config(device: Device, calib_params: CalibrationParams):
    chip_config = bytearray(DEFAULT_CONFIG)
    replace_value_in_section(chip_config, 2, TCODE_TAG, calib_params.tcode)
    replace_value_in_section(chip_config, 3, TCODE_TAG, calib_params.tcode)
    replace_value_in_section(chip_config, 4, TCODE_TAG, calib_params.tcode)
    replace_value_in_section(chip_config, 2, DAC_L_TAG, calib_params.dac_l << 4 | 8)
    replace_value_in_section(chip_config, 3, DAC_L_TAG, calib_params.dac_l << 4 | 8)
    replace_value_in_section(
        chip_config, 2, DELTA_DOWN_TAG, calib_params.delta_down << 8 | 0x80
    )
    fix_config_checksum(chip_config)

    device.upload_config(chip_config, 0.5)


def get_fdt_base_with_tx(
    device: Device, tx_enable: bool, calib_params: CalibrationParams
):
    op_code = 0xD
    if not tx_enable:
        op_code |= 0x80

    payload = op_code.to_bytes(length=1, byteorder="little")
    payload += calib_params.fdt_base_manual
    return device.execute_fdt_operation(FingerDetectionOperation.MANUAL, payload, 0.5)


def get_adjusted_dac(sensor_image: list[int], calib_image: list[int], dac: int):
    raise NotImplementedError


HV_VALUE = 6


def get_image(
    device: Device,
    tx_enable: bool,
    hv_enable: bool,
    use_dac: str,
    adjust_dac: bool,
    is_finger: bool,
    calib_params: CalibrationParams,
):
    if tx_enable:
        op_code = 0x1
    else:
        op_code = 0x81

    if is_finger:
        op_code |= 0x40

    if hv_enable:
        hv_value = HV_VALUE
    else:
        hv_value = 0x10

    if use_dac == "h":
        dac = calib_params.dac_h
    elif use_dac == "l":
        dac = calib_params.dac_l
    else:
        raise Exception("Invalid DAC type")

    request = op_code.to_bytes(length=1, byteorder="little")
    request += hv_value.to_bytes(length=1, byteorder="little")
    request += dac.to_bytes(length=2, byteorder="little")
    image = decode_image(device.get_image(request, 0.5))

    if adjust_dac:
        assert calib_params.calib_image is not None
        adjusted_dac = get_adjusted_dac(image, calib_params.calib_image, dac)
        if use_dac == "h":
            calib_params.dac_h = adjusted_dac
        elif use_dac == "l":
            calib_params.dac_l = adjusted_dac
        else:
            raise Exception("Invalid DAC type")

    return image


def is_fdt_base_valid(fdt_data_1: bytes, fdt_data_2: bytes, max_delta: int):
    assert len(fdt_data_1) == len(fdt_data_2)
    logging.debug(f"Checking FDT data, max delta: {max_delta}")
    for idx in range(0, len(fdt_data_1), 2):
        fdt_val_1 = int.from_bytes(fdt_data_1[idx : idx + 2], byteorder="little")
        fdt_val_2 = int.from_bytes(fdt_data_2[idx : idx + 2], byteorder="little")

        delta = abs((fdt_val_2 >> 1) - (fdt_val_1 >> 1))
        if delta > max_delta:
            return False
    return True


def validate_base_img(
    base_image_1: list[int], base_image_2: list[int], image_threshold: int
):
    assert len(base_image_1) == SENSOR_WIDTH * SENSOR_HEIGHT
    assert len(base_image_2) == SENSOR_WIDTH * SENSOR_HEIGHT

    diff_sum = 0
    for row_idx in range(2, SENSOR_HEIGHT - 2):
        for col_idx in range(2, SENSOR_WIDTH - 2):
            offset = row_idx * SENSOR_WIDTH + col_idx
            image_val_1 = base_image_1[offset]
            image_val_2 = base_image_2[offset]
            diff_sum += abs(image_val_2 - image_val_1)

    avg = diff_sum / ((SENSOR_HEIGHT - 4) * (SENSOR_WIDTH - 4))
    logging.debug(f"Checking image data, avg: {avg:.2f}, threshold: {image_threshold}")
    if avg > image_threshold:
        raise Exception("Invalid base image")


def generate_fdt_base(fdt_data: bytes):
    fdt_base = b""
    for idx in range(0, len(fdt_data), 2):
        fdt_val = int.from_bytes(fdt_data[idx : idx + 2], byteorder="little")
        fdt_base_val = (fdt_val & 0xFFFE) * 0x80 | fdt_val >> 1
        fdt_base += fdt_base_val.to_bytes(length=2, byteorder="little")
    return fdt_base


def update_all_base(device: Device, calib_params: CalibrationParams):
    upload_config(device, calib_params)

    fdt_data_tx_enabled = get_fdt_base_with_tx(device, True, calib_params)

    image_tx_enabled = get_image(device, True, True, "l", False, False, calib_params)

    fdt_data_tx_disabled = get_fdt_base_with_tx(device, False, calib_params)

    fdt_base_valid = is_fdt_base_valid(
        fdt_data_tx_enabled, fdt_data_tx_disabled, calib_params.delta_fdt
    )
    if not fdt_base_valid:
        raise Exception("Invalid FDT")

    image_tx_disabled = get_image(device, False, True, "l", False, False, calib_params)

    validate_base_img(image_tx_enabled, image_tx_disabled, calib_params.delta_img)

    fdt_data_tx_enabled_2 = get_fdt_base_with_tx(device, True, calib_params)

    fdt_base_valid = is_fdt_base_valid(
        fdt_data_tx_enabled_2, fdt_data_tx_disabled, calib_params.delta_fdt
    )
    if not fdt_base_valid:
        raise Exception("Invalid FDT")

    calib_params.update_fdt_bases(generate_fdt_base(fdt_data_tx_enabled))
    calib_params.calib_image = image_tx_enabled

    print(f"FDT manual base: {calib_params.fdt_base_manual.hex(' ', 2)}")
    print("Decoding and saving calibration image")
    write_pgm(calib_params.calib_image, SENSOR_HEIGHT, SENSOR_WIDTH, "clear.pgm")


def device_init(device: Device):
    device.ping()

    firmware_version = device.read_firmware_version()
    print(f"Firmware version: {firmware_version}")
    if re.fullmatch(VALID_FIRMWARE, firmware_version) is None:
        raise Exception("Chip does not have a valid firmware")

    device_enable(device)

    print("Checking sensor")
    calib_params = check_sensor(device)
    print("Sensor check successful")

    print("Checking PSK hash")
    if not is_valid_psk(device):
        print("Updating PSK")
        write_psk(device)
    print("All-zero PSK set up")

    print("Establishing GTLS connection")
    device.establish_gtls_connection(PSK)
    print("Connection successfully established")

    print("Updating all base")
    update_all_base(device, calib_params)
    print("Update completed")

    print("Set to sleep mode")
    device.set_sleep_mode(0.2)

    return calib_params


def generate_fdt_up_base(fdt_data, touch_flag, calib_params: CalibrationParams):
    fdt_vals = []
    for idx in range(0, len(fdt_data), 2):
        fdt_val = int.from_bytes(fdt_data[idx : idx + 2], byteorder="little")
        fdt_vals.append(fdt_val)

    fdt_base_up_vals = []
    for fdt_val in fdt_vals:
        val = (fdt_val >> 1) + calib_params.delta_down
        fdt_base_up_vals.append(val * 0x100 | val)

    for idx in range(0xC):
        if ((touch_flag >> idx) & 1) == 0:
            fdt_base_up_vals[idx] = (
                calib_params.delta_up * 0x100 | calib_params.delta_up
            )

    fdt_base_up = b""
    for fdt_val in fdt_base_up_vals:
        fdt_base_up += fdt_val.to_bytes(2, "little")

    return fdt_base_up


def wait_for_finger_down(device: Device, calib_params: CalibrationParams):
    fdt_data, touch_flag = device.wait_for_fdt_event(FingerDetectionOperation.DOWN)
    calib_params.fdt_base_up = generate_fdt_up_base(fdt_data, touch_flag, calib_params)
    return fdt_data


def wait_for_finger_up(device: Device, calib_params: CalibrationParams):
    fdt_data, _ = device.wait_for_fdt_event(FingerDetectionOperation.UP)
    calib_params.fdt_base_down = generate_fdt_base(fdt_data)
    return fdt_data


def main(product: int) -> None:
    if "DEBUG" in os.environ:
        logging.basicConfig(level=logging.DEBUG)

    device = Device(product, USBProtocol)
    calib_params = device_init(device)

    print("Powering on sensor")
    device.ec_control("on", 0.2)

    print("Setting up finger down detection")
    device.execute_fdt_operation(
        FingerDetectionOperation.DOWN, calib_params.fdt_base_down, 0.5
    )

    print("Waiting for finger down")
    event_fdt_data = wait_for_finger_down(device, calib_params)

    manual_fdt_data = get_fdt_base_with_tx(device, False, calib_params)
    fdt_base_valid = is_fdt_base_valid(
        event_fdt_data, manual_fdt_data, calib_params.delta_fdt
    )
    if fdt_base_valid:
        raise Exception("Temperature event")

    print("Reading finger image")
    # TODO: DAC dynamic adjustment should be True
    finger_image = get_image(device, True, True, "h", False, True, calib_params)
    write_pgm(finger_image, SENSOR_HEIGHT, SENSOR_WIDTH, "raw_finger.pgm")

    print("Setting up finger up detection")
    device.execute_fdt_operation(
        FingerDetectionOperation.UP, calib_params.fdt_base_up, 0.5
    )

    print("Waiting for finger up")
    event_fdt_data = wait_for_finger_up(device, calib_params)

    print("Set to sleep mode")
    device.set_sleep_mode(0.2)

    print("Powering off sensor")
    time.sleep(0.5)
    device.ec_control("off", 0.2)

    print("Done")
