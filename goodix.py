import struct
import threading

import time

import usb.core
import usb.util

INTERFACE_NUMBER = 1
DEBUG = True


class GoodixDevice:
    def __init__(self, id_vendor, id_product):
        dev = usb.core.find(idVendor=id_vendor, idProduct=id_product)

        if dev is None:
            raise SystemError("Device not found")

        print(
            f"Found '{dev.product}' from '{dev.manufacturer}' on bus {dev.bus} address {dev.address}."
        )

        dev.set_configuration()

        cfg = dev.get_active_configuration()

        intf = cfg.interfaces()[INTERFACE_NUMBER]

        self.ep_in = usb.util.find_descriptor(
            intf,
            custom_match=lambda ep: usb.util.endpoint_direction(
                ep.bEndpointAddress) == usb.util.ENDPOINT_IN)

        if self.ep_in is None:
            raise SystemError(
                "Cannot find device endpoint in (The interface number might be wrong)"
            )

        print(f"Found endpoint in: {hex(self.ep_in.bEndpointAddress)}")

        self.ep_out = usb.util.find_descriptor(
            intf,
            custom_match=lambda ep: usb.util.endpoint_direction(
                ep.bEndpointAddress) == usb.util.ENDPOINT_OUT)

        if self.ep_out is None:
            raise SystemError(
                "Cannot find device endpoint out (The interface number might be wrong)"
            )

        print(f"Found endpoint out: {hex(self.ep_out.bEndpointAddress)}")

        self.received_packets = []

        threading.Thread(target=self._read).start()

    def _read(self):
        while True:
            try:
                self.received_packets.append(bytes(self.ep_in.read(8192)))
            except usb.core.USBTimeoutError:
                break

    def unknown_0(self):  # nop ??
        return self.send_packet(
            self.construct_packet(0x96, bytes.fromhex("0100")))

    def get_fw_1(self):
        return self.send_packet(
            self.construct_packet(0xa8, bytes.fromhex("0000")))

    def read_psk_2(self):
        return self.send_packet(
            self.construct_packet(0xe4, bytes.fromhex("030002bb00000000")))

    def reset_3(self):
        return self.send_packet(
            self.construct_packet(0xa2, bytes.fromhex("0114")))

    def read_reg_4(self):
        return self.send_packet(
            self.construct_packet(0x82, bytes.fromhex("0000000400")))

    def read_otp_5(self):
        return self.send_packet(
            self.construct_packet(0xa6, bytes.fromhex("0000")))

    def reset_6(self):
        return self.send_packet(
            self.construct_packet(0xa2, bytes.fromhex("0114")))

    def unknown_7(self):
        return self.send_packet(
            self.construct_packet(0x70, bytes.fromhex("1400")))

    def unknown_8(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("002002780b")))

    def unknown_9(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003602b900")))

    def unknown_10(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003802b700")))

    def unknown_11(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003a02b700")))

    def mcu_chip_config_12(self):
        return self.send_packet(
            self.construct_packet(
                0x90,
                bytes.fromhex(
                    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca000400840015b3860000c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000b6980000009a000000d2000000d4000000d6000000d800000050000105d0000000700000007200785674003412200010402a0102042200012024003200800001005c008000560004205800030232000c02660003007c000058820080152a0182032200012024001400800001005c000001560004205800030232000c02660003007c0000588200801f2a0108005c008000540010016200040364001900660003007c0001582a0108005c0000015200080054000001660003007c00015800892e"
                )))

    def unknown_13(self):
        return self.send_packet(
            self.construct_packet(0x94, bytes.fromhex("6400")))

    def request_tls_connect_14(self):
        return self.send_packet(
            self.construct_packet(0xd0, bytes.fromhex("0000")))

    def send_packet(self, packet, timeout=0.1):

        if DEBUG: print(f"Sending: {packet.hex()}")

        if len(packet) % 64:
            packet = packet + b"\x00" * (64 - len(packet) % 64)

        self.received_packets = []

        for i in range(0, len(packet), 64):
            self.ep_out.write(packet[i:i + 64])

        time.sleep(timeout)

        if DEBUG:
            for received_packet in self.received_packets:
                print(f"Received: {received_packet}")

        return self.received_packets

    def construct_packet(self, command, data):
        payload = bytes([command])

        payload += struct.pack("<H", len(data) + 1)
        payload += data

        payload += bytes([0xaa - sum(payload) & 0xff])

        usbheader = bytes([0xa0])
        usbheader += struct.pack("<H", len(payload))
        usbheader += bytes([sum(usbheader) & 0xff])

        return usbheader + payload


def main():
    dev = GoodixDevice(0x27c6, 0x5110)
    print(dev.unknown_0())
    print(dev.get_fw_1())
    print(dev.read_psk_2())
    print(dev.reset_3())
    print(dev.read_reg_4())
    print(dev.read_otp_5())
    print(dev.reset_6())
    print(dev.unknown_7())
    print(dev.unknown_8())
    print(dev.unknown_9())
    print(dev.unknown_10())
    print(dev.unknown_11())
    print(dev.unknown_11())
    print(dev.mcu_chip_config_12())
    print(dev.unknown_13())
    print(dev.request_tls_connect_14())


if __name__ == "__main__":
    main()
