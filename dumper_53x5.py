import logging
import os

import protocol
import wrapless

import crccheck

IAP_START = 0x0
IAP_END = 0x3000
IAP_FILE = "iap_firmware.bin"
APP_FILE = "app_firmware.bin"

PAGE_SIZE = 0x200
NUM_PAGES = 0xFF


def dump_iap_firmware(device):
    print(f"Dumping IAP firmware from {hex(IAP_START)} to {hex(IAP_END)}")
    dump = b""
    for page_start in range(IAP_START, IAP_END, 0x400):
        dump += device.read_firmware(page_start, 0x400)

    print(f"Writing dumped IAP firmware to {IAP_FILE}")
    with open(IAP_FILE, "wb") as dump_file:
        dump_file.write(dump)


def extract_firmware_info(last_flash_page):
    firmware_length = int.from_bytes(
        last_flash_page[PAGE_SIZE - 8 : PAGE_SIZE - 4], byteorder="little"
    )
    firmware_crc32 = int.from_bytes(
        last_flash_page[PAGE_SIZE - 4 : PAGE_SIZE], byteorder="little"
    )

    firmware_length_not = int.from_bytes(
        last_flash_page[PAGE_SIZE - 0x10 : PAGE_SIZE - 0xC], byteorder="little"
    )
    firmware_crc32_not = int.from_bytes(
        last_flash_page[PAGE_SIZE - 0xC : PAGE_SIZE - 0x8], byteorder="little"
    )

    assert firmware_length == firmware_length_not ^ 0xFFFFFFFF
    assert firmware_crc32 == firmware_crc32_not ^ 0xFFFFFFFF

    return (firmware_length, firmware_crc32)


def dump_app_firmware(device, firmware_length, firmware_crc32):
    print(
        f"Dumping APP firmware from {hex(IAP_END)} to {hex(IAP_END + firmware_length)}"
    )
    dump = b""
    for page_start in range(IAP_END, IAP_END + firmware_length, 0x400):
        dump += device.read_firmware(page_start, 0x400)

    dump = dump[:firmware_length]

    dump_crc32 = crccheck.crc.Crc32Mpeg2.calc(dump)
    if dump_crc32 != firmware_crc32:
        raise Exception("Invalid CRC32!")

    print(f"Writing dumped APP firmware to {APP_FILE}")
    with open(APP_FILE, "wb") as dump_file:
        dump_file.write(dump)


def parse_mask(mask: bytes):
    n_bits = len(mask) * 8
    mask_val = int.from_bytes(mask, byteorder="little")
    for _ in range(n_bits):
        yield mask_val & 1 == 1
        mask_val >>= 1


def print_masked_buffer(content: bytes, mask: bytes):
    for c, m in zip(content, parse_mask(mask)):
        if m:
            print(f"{c:02x}", end=" ")
        else:
            print("--", end=" ")
    print()


def parse_0x20_flash_buffer(data):
    tag_1 = int.from_bytes(data[:0x4], byteorder="little")
    tag_2 = int.from_bytes(data[0x4:0x8], byteorder="little")

    assert tag_1 & 0xFFFF == (tag_1 >> 0x10) ^ 0xFFFF
    assert tag_2 & 0xFFFF == (tag_2 >> 0x10) ^ 0xFFFF

    saved_crc = int.from_bytes(data[0x30:0x34], byteorder="little")
    saved_content = data[0xC:0x2C]
    saved_mask = data[0x2C:0x30]

    crc = crccheck.crc.Crc32Mpeg2.calc(data[0x4:0x30])
    if crc != saved_crc:
        raise Exception("Invalid CRC32!")

    return (saved_content, saved_mask)


def dump_otp(device):
    otp_base = PAGE_SIZE * (NUM_PAGES - 3)
    print(f"Dumping OTP from flash ({hex(otp_base)})")
    pages = device.read_firmware(otp_base, PAGE_SIZE * 2)

    page_1 = pages[:PAGE_SIZE]
    content, mask = parse_0x20_flash_buffer(page_1)

    print("OTP: ", end="")
    print_masked_buffer(content, mask)


def dump_usb_pid(device):
    usb_pid_base = PAGE_SIZE * (NUM_PAGES - 5)
    print(f"Dumping USB PID from flash ({hex(usb_pid_base)})")
    pages = device.read_firmware(usb_pid_base, PAGE_SIZE * 2)

    page_1 = pages[:PAGE_SIZE]
    content, mask = parse_0x20_flash_buffer(page_1)

    print("USB PID: ", end="")
    print_masked_buffer(content, mask)


def dump_option_byte(device):
    print(f"Dumping option byte")
    option_byte = device.read_option_byte()
    print(option_byte)


def main(product: int):
    if "DEBUG" in os.environ:
        logging.basicConfig(level=logging.DEBUG)

    device = wrapless.Device(product, protocol.USBProtocol)
    device.ping()

    firmware_version = device.read_firmware_version()
    print(f"Firmware version: {firmware_version}")

    dump_otp(device)

    dump_usb_pid(device)

    dump_iap_firmware(device)

    last_two_pages = device.read_firmware(PAGE_SIZE * (NUM_PAGES - 1), PAGE_SIZE * 2)

    last_flash_page = last_two_pages[:PAGE_SIZE]
    firmware_length, firmware_crc32 = extract_firmware_info(last_flash_page)
    print(f"APP firmware length: {hex(firmware_length)}")
    print(f"APP firmware CRC32: {hex(firmware_crc32)}")

    dump_app_firmware(device, firmware_length, firmware_crc32)

    option_byte_page = last_two_pages[PAGE_SIZE:]
    print(f"Option Byte page: {option_byte_page[:0x24]}")

    dump_option_byte(device)
