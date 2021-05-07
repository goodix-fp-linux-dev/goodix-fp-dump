from struct import pack
from threading import Thread
from time import sleep

from usb.core import USBTimeoutError, find
from usb.util import (ENDPOINT_IN, ENDPOINT_OUT, endpoint_direction,
                      find_descriptor)

INTERFACE_NUMBER = 1


class GoodixDevice:
    def __init__(self, id_vendor, id_product):
        dev = find(idVendor=id_vendor, idProduct=id_product)

        if dev is None:
            raise SystemError("Device not found")

        print(
            f"Found '{dev.product}' from '{dev.manufacturer}' on bus {dev.bus} address {dev.address}."
        )

        dev.set_configuration()

        cfg = dev.get_active_configuration()

        interface = cfg.interfaces()[INTERFACE_NUMBER]

        self.ep_in = find_descriptor(
            interface,
            custom_match=lambda ep: endpoint_direction(ep.bEndpointAddress
                                                       ) == ENDPOINT_IN)

        if self.ep_in is None:
            raise SystemError(
                "Cannot find device endpoint in (The interface number might be wrong)"
            )

        print(f"Found endpoint in: {hex(self.ep_in.bEndpointAddress)}")

        self.ep_out = find_descriptor(
            interface,
            custom_match=lambda ep: endpoint_direction(ep.bEndpointAddress
                                                       ) == ENDPOINT_OUT)

        if self.ep_out is None:
            raise SystemError(
                "Cannot find device endpoint out (The interface number might be wrong)"
            )

        print(f"Found endpoint out: {hex(self.ep_out.bEndpointAddress)}")

        self.received_packets = []

        Thread(target=self._read_loop).start()

    def _read_loop(self):
        while True:
            try:
                self.received_packets.append(bytes(self.ep_in.read(8192)))
            except USBTimeoutError:
                break

    def send_packet(self, packet, timeout=0.1):

        if len(packet) % 64:
            packet = packet + b"\x00" * (64 - len(packet) % 64)

        self.received_packets = []

        for i in range(0, len(packet), 64):
            self.ep_out.write(packet[i:i + 64])

        sleep(timeout)

        return self.received_packets

    def construct_packet(self, command, data):
        payload = bytes([command])

        payload += pack("<H", len(data) + 1)
        payload += data

        payload += bytes([0xaa - sum(payload) & 0xff])

        usbheader = bytes([0xa0])
        usbheader += pack("<H", len(payload))
        usbheader += bytes([sum(usbheader) & 0xff])

        return usbheader + payload

    def nop(self):
        return self.send_packet(
            self.construct_packet(0x00, bytes.fromhex("00000000")))

    def enableChip(self):
        return self.send_packet(
            self.construct_packet(0x96, bytes.fromhex("0100")))

    def getFirmwareVersion(self):
        return self.send_packet(
            self.construct_packet(0xa8, bytes.fromhex("0000")))

    def presetPskReadR(self):
        return self.send_packet(
            self.construct_packet(0xe4, bytes.fromhex("030002bb00000000")))

    def reset(self):
        return self.send_packet(
            self.construct_packet(0xa2, bytes.fromhex("0114")))

    def readSensorRegister_0(self):
        return self.send_packet(
            self.construct_packet(0x82, bytes.fromhex("0000000400")))

    def readOtp(self):
        return self.send_packet(
            self.construct_packet(0xa6, bytes.fromhex("0000")))

    def mcuSwitchToIdleMode(self):
        return self.send_packet(
            self.construct_packet(0x70, bytes.fromhex("1400")))

    def reg0_0(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("002002780b")))

    def reg0_1(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003602b900")))

    def reg0_2(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003802b700")))

    def reg0_3(self):
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003a02b700")))

    def mcuDownloadChipConfig(self):
        return self.send_packet(
            self.construct_packet(
                0x90,
                bytes.fromhex(
                    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca000400840015b3860000c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000b6980000009a000000d2000000d4000000d6000000d800000050000105d0000000700000007200785674003412200010402a0102042200012024003200800001005c008000560004205800030232000c02660003007c000058820080152a0182032200012024001400800001005c000001560004205800030232000c02660003007c0000588200801f2a0108005c008000540010016200040364001900660003007c0001582a0108005c0000015200080054000001660003007c00015800892e"
                )))

    def setPowerdownScanFrequency(self):
        return self.send_packet(
            self.construct_packet(0x94, bytes.fromhex("6400")))

    def requestTlsConnection(self):  # TODO
        return self.send_packet(
            self.construct_packet(0xd0, bytes.fromhex("0000")))

    def TlsSuccessfullyEstablished(self):  # TODO
        return self.send_packet(
            self.construct_packet(0xd4, bytes.fromhex("0000")))

    def queryMcuState(self):
        return self.send_packet(
            self.construct_packet(0xae, bytes.fromhex("55")))

    def mcuSwitchToFdtMode_0(self):
        return self.send_packet(
            self.construct_packet(
                0x36, bytes.fromhex("0d01aeaebfbfa4a4b8b8a8a8b7b7")))

    def nav0(self):
        return self.send_packet(
            self.construct_packet(0x50, bytes.fromhex("0100")))

    def mcuSwitchToFdtMode_1(self):
        return self.send_packet(
            self.construct_packet(
                0x36, bytes.fromhex("0d0180af80bf80a380b780a780b6")))

    def readSensorRegister_1(self):
        return self.send_packet(
            self.construct_packet(0x82, bytes.fromhex("0082000200")))

    def mcuGetImage(self):
        return self.send_packet(
            self.construct_packet(0x20, bytes.fromhex("0100")))

    def mcuSwitchToFdtMode_2(self):
        return self.send_packet(
            self.construct_packet(
                0x36, bytes.fromhex("0d0180af80bf80a480b880a880b7")))

    def mcuSwitchToFdtDown(self):
        return self.send_packet(
            self.construct_packet(
                0x32, bytes.fromhex("0c0180af80bf80a480b880a880b7")))


def main():
    dev = GoodixDevice(0x27c6, 0x5110)
    print(dev.nop())
    print(dev.enableChip())
    print(dev.nop())
    print(dev.getFirmwareVersion())
    print(dev.presetPskReadR())
    print(dev.reset())
    print(dev.readSensorRegister_0())
    print(dev.readOtp())
    print(dev.reset())
    print(dev.mcuSwitchToIdleMode())
    print(dev.reg0_0())
    print(dev.reg0_1())
    print(dev.reg0_2())
    print(dev.reg0_3())
    print(dev.mcuDownloadChipConfig())
    print(dev.setPowerdownScanFrequency())
    print(dev.queryMcuState())
    print(dev.mcuSwitchToFdtMode_0())
    print(dev.nav0())
    print(dev.mcuSwitchToFdtMode_1())
    print(dev.readSensorRegister_1())
    print(dev.mcuGetImage())
    print(dev.mcuSwitchToFdtMode_2())
    print(dev.mcuSwitchToFdtDown())


if __name__ == "__main__":
    main()
