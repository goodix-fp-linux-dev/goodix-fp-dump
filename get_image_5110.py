from socket import socket
from subprocess import PIPE, STDOUT, Popen
from sys import exit as sys_exit

from goodix import Device
from goodix.core import decode_image
from goodix.dev_5110 import (TARGET_PSK, check_firmware, check_psk, init_device,
                             setup_device, connect_device, write_pgm)


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

        setup_device(device)

        tls_client = socket()
        tls_client.connect(("localhost", 4433))

        connect_device(device, tls_client)

        device.query_mcu_state()

        device.mcu_switch_to_fdt_mode(
            b"\x0d\x01\xae\xae\xbf\xbf\xa4\xa4\xb8\xb8\xa8\xa8\xb7\xb7")

        device.nav_0()

        device.mcu_switch_to_fdt_mode(
            b"\x0d\x01\x80\xaf\x80\xbf\x80\xa3\x80\xb7\x80\xa7\x80\xb6")

        device.read_sensor_register(0x0082)

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
