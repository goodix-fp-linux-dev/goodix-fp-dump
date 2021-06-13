from socket import socket
from subprocess import PIPE, STDOUT, Popen
from sys import exit as sys_exit
from time import sleep

from goodix import Device
from goodix.core import (FLAGS_TRANSPORT_LAYER_SECURITY, check_message_pack,
                         encode_message_pack)
from goodix.dev_5110 import TARGET_PSK, check_firmware, check_psk, init_device

SENSOR_HEIGHT = 88
SENSOR_WIDTH = 80


def decode_image(data: bytes) -> list:
    assert (len(data) % 6) == 0

    image = []
    for i in range(0, len(data), 6):
        chunk = data[i:i + 6]

        image.append(((chunk[0] & 0xf) << 8) + chunk[1])
        image.append((chunk[3] << 4) + (chunk[0] >> 4))
        image.append(((chunk[5] & 0xf) << 8) + chunk[2])
        image.append((chunk[4] << 4) + (chunk[5] >> 4))

    return image


def write_pgm(image: list, file_name: str) -> None:
    file = open(f"{file_name}.pgm", "w")

    file.write(f"P2\n{SENSOR_HEIGHT} {SENSOR_WIDTH}\n4095\n")
    file.write("\n".join(map(str, image)))

    file.close()


def main(product: int) -> int:
    tls_server = Popen([
        "openssl", "s_server", "-nocert", "-psk",
        TARGET_PSK.hex(), "-port", "4433", "-quiet"
    ],
                       stdout=PIPE,
                       stderr=STDOUT)

    try:
        device = Device(product)

        init_device(device)

        firmware = check_firmware(device)

        valid_psk = check_psk(device)

        if firmware:
            print("Invalid firmware: Abort")
            return -1

        if not valid_psk:
            print("Invalid PSK: Abort")
            return -1

        device.reset()

        device.read_sensor_register(0x0000, 4)
        device.read_otp()
        device.reset()

        device.mcu_switch_to_idle_mode()

        device.write_sensor_register(0x0220, b"\x78\x0b")
        device.write_sensor_register(0x0236, b"\xb9\x00")
        device.write_sensor_register(0x0238, b"\xb7\x00")
        device.write_sensor_register(0x023a, b"\xb7\x00")

        device.upload_config_mcu(
            b"\x70\x11\x60\x71\x2c\x9d\x2c\xc9\x1c\xe5\x18\xfd\x00\xfd\x00\xfd"
            b"\x03\xba\x00\x01\x80\xca\x00\x04\x00\x84\x00\x15\xb3\x86\x00\x00"
            b"\xc4\x88\x00\x00\xba\x8a\x00\x00\xb2\x8c\x00\x00\xaa\x8e\x00\x00"
            b"\xc1\x90\x00\xbb\xbb\x92\x00\xb1\xb1\x94\x00\x00\xa8\x96\x00\x00"
            b"\xb6\x98\x00\x00\x00\x9a\x00\x00\x00\xd2\x00\x00\x00\xd4\x00\x00"
            b"\x00\xd6\x00\x00\x00\xd8\x00\x00\x00\x50\x00\x01\x05\xd0\x00\x00"
            b"\x00\x70\x00\x00\x00\x72\x00\x78\x56\x74\x00\x34\x12\x20\x00\x10"
            b"\x40\x2a\x01\x02\x04\x22\x00\x01\x20\x24\x00\x32\x00\x80\x00\x01"
            b"\x00\x5c\x00\x80\x00\x56\x00\x04\x20\x58\x00\x03\x02\x32\x00\x0c"
            b"\x02\x66\x00\x03\x00\x7c\x00\x00\x58\x82\x00\x80\x15\x2a\x01\x82"
            b"\x03\x22\x00\x01\x20\x24\x00\x14\x00\x80\x00\x01\x00\x5c\x00\x00"
            b"\x01\x56\x00\x04\x20\x58\x00\x03\x02\x32\x00\x0c\x02\x66\x00\x03"
            b"\x00\x7c\x00\x00\x58\x82\x00\x80\x1f\x2a\x01\x08\x00\x5c\x00\x80"
            b"\x00\x54\x00\x10\x01\x62\x00\x04\x03\x64\x00\x19\x00\x66\x00\x03"
            b"\x00\x7c\x00\x01\x58\x2a\x01\x08\x00\x5c\x00\x00\x01\x52\x00\x08"
            b"\x00\x54\x00\x00\x01\x66\x00\x03\x00\x7c\x00\x01\x58\x00\x89\x2e"
        )

        device.set_powerdown_scan_frequency()

        tls_client = socket()
        tls_client.connect(("localhost", 4433))

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

        device.mcu_switch_to_fdt_mode(
            b"\x0d\x01\xae\xae\xbf\xbf\xa4\xa4\xb8\xb8\xa8\xa8\xb7\xb7")

        device.nav_0()

        device.mcu_switch_to_fdt_mode(
            b"\x0d\x01\x80\xaf\x80\xbf\x80\xa3\x80\xb7\x80\xa7\x80\xb6")

        device.read_sensor_register(0x0082, 2)

        tls_client.sendall(device.mcu_get_image())

        write_pgm(decode_image(tls_server.stdout.read(10573)[8:-5]), "clear")

        device.mcu_switch_to_fdt_mode(
            b"\x0d\x01\x80\xaf\x80\xbf\x80\xa4\x80\xb8\x80\xa8\x80\xb7")

        print("Waiting for finger...")

        device.mcu_switch_to_fdt_down(
            b"\x0c\x01\x80\xaf\x80\xbf\x80\xa4\x80\xb8\x80\xa8\x80\xb7")

        tls_client.sendall(device.mcu_get_image())

        write_pgm(decode_image(tls_server.stdout.read(10573)[8:-5]),
                  "fingerprint")

        tls_client.close()

        return 0

    finally:
        tls_server.terminate()


if __name__ == "__main__":
    sys_exit(main(0x5110))
