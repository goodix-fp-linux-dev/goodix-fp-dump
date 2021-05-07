from struct import pack
from threading import Thread
from time import sleep, time
from warnings import warn

from usb.core import USBTimeoutError, find
from usb.util import (ENDPOINT_IN, ENDPOINT_OUT, endpoint_direction,
                      find_descriptor)

INTERFACE_NUMBER = 1

DEBUG_LEVEL = 3


class GoodixDevice:
    def __init__(self, id_vendor, id_product):
        dev = find(idVendor=id_vendor, idProduct=id_product)

        if dev is None:
            raise SystemError("Device not found")

        if DEBUG_LEVEL > 0:
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

        if DEBUG_LEVEL > 0:
            print(f"Found endpoint in: {hex(self.ep_in.bEndpointAddress)}")

        self.ep_out = find_descriptor(
            interface,
            custom_match=lambda ep: endpoint_direction(ep.bEndpointAddress
                                                       ) == ENDPOINT_OUT)

        if self.ep_out is None:
            raise SystemError(
                "Cannot find device endpoint out (The interface number might be wrong)"
            )

        if DEBUG_LEVEL > 0:
            print(f"Found endpoint out: {hex(self.ep_out.bEndpointAddress)}")

        self.received_packets = []

        Thread(target=self._read_loop).start()

    def _read_loop(self):
        while True:
            try:
                read = bytes(self.ep_in.read(8192))
            except USBTimeoutError:
                break

            if DEBUG_LEVEL > 2: print(f"_read_loop({read})")
            self.received_packets.append(read)

    def send_packet(self, packet, timeout=0.2, reply_count=None):

        if DEBUG_LEVEL > 2: print(f"send_packet({packet})")

        if len(packet) % 64:
            packet = packet + b"\x00" * (64 - len(packet) % 64)

        if self.received_packets:
            warn(
                RuntimeWarning(
                    f"Received {self.received_packets} after timeout. Try to increase the timeout"
                ))

        self.received_packets.clear()

        for i in range(0, len(packet), 64):
            self.ep_out.write(packet[i:i + 64])

        if reply_count is None:
            if timeout:
                sleep(timeout)
        elif timeout:
            abort_time = time() + timeout
            while len(self.received_packets) < reply_count:
                if time() >= abort_time:
                    break
                sleep(0.01)
        else:
            while len(self.received_packets) < reply_count:
                sleep(0.01)

        received_packets = list(self.received_packets)

        self.received_packets.clear()

        return received_packets

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
        if DEBUG_LEVEL > 1: print("nop()")
        return self.send_packet(
            self.construct_packet(0x00, bytes.fromhex("00000000")))

    def enableChip(self):
        if DEBUG_LEVEL > 1: print("enableChip()")
        return self.send_packet(
            self.construct_packet(0x96, bytes.fromhex("0100")))

    def getFirmwareVersion(self):
        if DEBUG_LEVEL > 1: print("getFirmwareVersion()")
        return self.send_packet(
            self.construct_packet(0xa8, bytes.fromhex("0000")))

    def presetPskReadR(self):
        if DEBUG_LEVEL > 1: print("presetPskReadR()")
        return self.send_packet(
            self.construct_packet(0xe4, bytes.fromhex("030002bb00000000")))

    def reset(self):
        if DEBUG_LEVEL > 1: print("reset()")
        return self.send_packet(
            self.construct_packet(0xa2, bytes.fromhex("0114")))

    def readSensorRegister_0(self):
        if DEBUG_LEVEL > 1: print("readSensorRegister_0()")
        return self.send_packet(
            self.construct_packet(0x82, bytes.fromhex("0000000400")))

    def readOtp(self):
        if DEBUG_LEVEL > 1: print("readOtp()")
        return self.send_packet(
            self.construct_packet(0xa6, bytes.fromhex("0000")))

    def mcuSwitchToIdleMode(self):
        if DEBUG_LEVEL > 1: print("mcuSwitchToIdleMode()")
        return self.send_packet(
            self.construct_packet(0x70, bytes.fromhex("1400")))

    def reg0_0(self):
        if DEBUG_LEVEL > 1: print("reg0_0()")
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("002002780b")))

    def reg0_1(self):
        if DEBUG_LEVEL > 1: print("reg0_1()")
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003602b900")))

    def reg0_2(self):
        if DEBUG_LEVEL > 1: print("reg0_2()")
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003802b700")))

    def reg0_3(self):
        if DEBUG_LEVEL > 1: print("reg0_3()")
        return self.send_packet(
            self.construct_packet(0x80, bytes.fromhex("003a02b700")))

    def mcuDownloadChipConfig(self):
        if DEBUG_LEVEL > 1: print("mcuDownloadChipConfig()")
        return self.send_packet(
            self.construct_packet(
                0x90,
                bytes.fromhex(
                    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca000400840015b3860000c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000b6980000009a000000d2000000d4000000d6000000d800000050000105d0000000700000007200785674003412200010402a0102042200012024003200800001005c008000560004205800030232000c02660003007c000058820080152a0182032200012024001400800001005c000001560004205800030232000c02660003007c0000588200801f2a0108005c008000540010016200040364001900660003007c0001582a0108005c0000015200080054000001660003007c00015800892e"
                )))

    def setPowerdownScanFrequency(self):
        if DEBUG_LEVEL > 1: print("setPowerdownScanFrequency()")
        return self.send_packet(
            self.construct_packet(0x94, bytes.fromhex("6400")))

    def requestTlsConnection(self):  # TODO
        if DEBUG_LEVEL > 1: print("requestTlsConnection()")
        return self.send_packet(
            self.construct_packet(0xd0, bytes.fromhex("0000")))

    def TlsSuccessfullyEstablished(self):  # TODO
        if DEBUG_LEVEL > 1: print("TlsSuccessfullyEstablished()")
        return self.send_packet(
            self.construct_packet(0xd4, bytes.fromhex("0000")))

    def queryMcuState(self):
        if DEBUG_LEVEL > 1: print("queryMcuState()")
        return self.send_packet(
            self.construct_packet(0xae, bytes.fromhex("55")))

    def mcuSwitchToFdtMode_0(self):
        if DEBUG_LEVEL > 1: print("mcuSwitchToFdtMode_0()")
        return self.send_packet(
            self.construct_packet(
                0x36, bytes.fromhex("0d01aeaebfbfa4a4b8b8a8a8b7b7")))

    def nav0(self):
        if DEBUG_LEVEL > 1: print("nav0()")
        return self.send_packet(
            self.construct_packet(0x50, bytes.fromhex("0100")))

    def mcuSwitchToFdtMode_1(self):
        if DEBUG_LEVEL > 1: print("mcuSwitchToFdtMode_1()")
        return self.send_packet(
            self.construct_packet(
                0x36, bytes.fromhex("0d0180af80bf80a380b780a780b6")))

    def readSensorRegister_1(self):
        if DEBUG_LEVEL > 1: print("readSensorRegister_1()")
        return self.send_packet(
            self.construct_packet(0x82, bytes.fromhex("0082000200")))

    def mcuGetImage(self):
        if DEBUG_LEVEL > 1: print("mcuGetImage()")
        return self.send_packet(
            self.construct_packet(0x20, bytes.fromhex("0100")))

    def mcuSwitchToFdtMode_2(self):
        if DEBUG_LEVEL > 1: print("mcuSwitchToFdtMode_2()")
        return self.send_packet(
            self.construct_packet(
                0x36, bytes.fromhex("0d0180af80bf80a480b880a880b7")))

    def mcuSwitchToFdtDown(self):
        if DEBUG_LEVEL > 1: print("mcuSwitchToFdtDown()")
        return self.send_packet(
            self.construct_packet(
                0x32, bytes.fromhex("0c0180af80bf80a480b880a880b7")))

    def presetPskWriteR(self):  # TODO
        if DEBUG_LEVEL > 1: print("presetPskWriteR()")
        return self.send_packet(
            self.construct_packet(
                0xe0,
                bytes.fromhex(
                    "020001bb4c01000001000000d08c9ddf0115d1118c7a00c04fc297eb0100000001c849b9831e694cb3ef601ff3e13c3c04000000400000005400680069007300200069007300200074006800650020006400650073006300720069007000740069006f006e00200073007400720069006e0067002e000000106600000001000020000000de9c7b6a74cb5731d2ba9089f678355db919ca22a96fbc86781e8223b741cf2c000000000e8000000002000020000000bf025282946c5c5fe36ec3f2b80c11f14f9608819f1790d62a1034e3a4c5635e30000000169b4c61cd4724f4d4f66f0a221e190684de7b78ec78dd050fd43a1d615edb065d472709638b1ccf0b078d1a6aef448340000000ac1ffaf61fe4d85e4588ccbd32beed369bb1f5416ef1576a5c9b091cee76f67075bf4b2fe5412556daed191cbe7908ad6e8f2fc9a33fde2d4999e5de4726c401e11e27deafe555f5030001bb60000000ec35ae3abb45ed3f12c4751f1e5c2cc052028389a3b33f0f0649eab30207a3625a7f2838fa061d1e0b870838464ff11e609e379f7e971a156ee01cf58604b5816839e8e27af8f68dd55019a127350a6bf67938335bb0c67c5cfe5911dab3f239"
                )))


def windowInit(dev):
    dev.nop()
    dev.enableChip()
    dev.nop()
    dev.getFirmwareVersion()
    dev.presetPskReadR()
    dev.reset()
    dev.readSensorRegister_0()
    dev.readOtp()
    dev.reset()
    dev.mcuSwitchToIdleMode()
    dev.reg0_0()
    dev.reg0_1()
    dev.reg0_2()
    dev.reg0_3()
    dev.mcuDownloadChipConfig()
    dev.setPowerdownScanFrequency()
    dev.queryMcuState()
    dev.mcuSwitchToFdtMode_0()
    dev.nav0()
    dev.mcuSwitchToFdtMode_1()
    dev.readSensorRegister_1()
    dev.mcuGetImage()
    dev.mcuSwitchToFdtMode_2()
    dev.mcuSwitchToFdtDown()


def customInit(dev):
    print(dev.nop())
    print(dev.enableChip())
    print(dev.nop())
    print(dev.getFirmwareVersion())
    print(dev.presetPskReadR())
    print(dev.presetPskReadR()
          )  # Twice because maybe Windows think the data is corrupted
    print(dev.presetPskWriteR())
    print(dev.presetPskReadR())


def tryToOverWriteFuckingPsk(dev):
    dev.send_packet(
        bytes.fromhex(
            "a00800a8000500000000008800000000000000000000000000000000000000000000000000000000000000000000000000000000000000003026481fff7f0000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00600a6960300010010855b5b010000480000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00800a80005000000000088000000000000000000000000000000000000000052fc17ae400000004c51f0fafe7f000030c9855b5b0100000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00600a6a803000000ff855b5b0100004800000000000000010000005b01000000000000000000000b34f41cff7f000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00c00ace40900030002bb00000000fd0000000000000000000000000000000000000000000000000b34f41cff7f000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00c00ace40900030002bb00000000fd0000000000000000000000000000000000000000000000000b34f41cff7f000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00600a6a40300000003000000000000000000000000000000000000000000008a9df7cde2e8000000000000000000000000000000000000d34beffafe7f0000"
        ))


def retryToOverWriteFuckingPsk(dev):
    dev.send_packet(
        bytes.fromhex(
            "a00800a8000500000000008800000000000000000000000000000000000000000000000000000000000000000000000000000000000000003026481fff7f0000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00600a69603000100103207cc010000480000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00800a80005000000000088000000000000000000000000000000000000000062f507fe8f0000004c5152fafe7f000010233107cc0100000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00600a6a803000000ff3207cc010000480000000000000001000000cc01000000000000000000000b34f41cff7f000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00c00ace40900030002bb00000000fd0000000000000000000000000000000000000000000000000b34f41cff7f000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00c00ace40900030002bb00000000fd0000000000000000000000000000000000000000000000000b34f41cff7f000000000000000000000000000000000000"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a0c00161e0bd01020001bb4c01000001000000d08c9ddf0115d1118c7a00c04fc297eb0100000001c849b9831e694cb3ef601ff3e13c3c04000000400000005400680069007300200069007300200074006800650020006400650073006300720069007000740069006f006e00200073007400720069006e0067002e000000106600000001000020000000de9c7b6a74cb5731d2ba9089f678355db919ca22a96fbc86781e8223b741cf2c000000000e8000000002000020000000bf025282946c5c5fe36ec3f2b80c11f14f9608819f1790d62a1034e3a4c5635e30000000169b4c61cd4724f4d4f66f0a221e190684de7b78ec78dd050fd43a1d615edb065d472709638b1ccf0b078d1a6aef448340000000ac1ffaf61fe4d85e4588ccbd32beed369bb1f5416ef1576a5c9b091cee76f67075bf4b2fe5412556daed191cbe7908ad6e8f2fc9a33fde2d4999e5de4726c401e11e27deafe555f5030001bb60000000ec35ae3abb45ed3f12c4751f1e5c2cc052028389a3b33f0f0649eab30207a3625a7f2838fa061d1e0b870838464ff11e609e379f7e971a156ee01cf58604b5816839e8e27af8f68dd55019a127350a6bf67938335bb0c67c5cfe5911dab3f239a97f2838fa061d1e0b870838464ff11e609e379f7e971a156ee01cf58604b5816839e8e27af8f68dd55019a127350a6bf67938335bb0c67c5cfe5911da"
        ))
    dev.send_packet(
        bytes.fromhex(
            "a00c00ace40900030002bb00000000fd0000000000000000000000000000000000000000000000000b34f41cff7f000000000000000000000000000000000000"
        ))


def main():
    dev = GoodixDevice(0x27c6, 0x5110)
    print(
        "############################################################################################"
    )
    start_PSK = dev.presetPskReadR()[1].hex()
    print("Start PSK:")
    print(start_PSK)
    print(
        "############################################################################################"
    )
    # windowInit(dev)
    # customInit(dev)
    tryToOverWriteFuckingPsk(dev)
    sleep(5)
    del dev
    sleep(5)
    devagain = GoodixDevice(0x27c6, 0x5110)
    retryToOverWriteFuckingPsk(devagain)
    print(
        "############################################################################################"
    )
    end_PSK = devagain.presetPskReadR()[1].hex()
    print("End PSK:")
    print(end_PSK)
    print(
        "############################################################################################"
    )
    if start_PSK != end_PSK:
        print("Well... PSK are different")


if __name__ == "__main__":
    main()
