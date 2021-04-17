import usb.core
import usb.util
import struct

INTERFACE_NUMBER = 1


def construct_cmd_payload(cmd, data):
    payload = bytes((cmd, ))

    targetlen = len(data) + 1  # includes checksum byte
    payload += struct.pack("<h", targetlen)
    payload += data

    chksum = 0xaa - sum(payload) & 0xff
    payload += bytes((chksum, ))

    # payload has to be wrapped in usb protocol thingy
    usbheader = bytes((0xa0, ))
    usbheader += struct.pack("<h", len(payload))
    usbheader += bytes(
        (sum(usbheader) & 0xff, ))  # checksum of wrapper is simple sum

    return usbheader + payload


def find_device(idVendor, idProduct):
    dev = usb.core.find(idVendor=idVendor, idProduct=idProduct)
    assert dev is not None

    print(
        f"Found '{dev.product}' from '{dev.manufacturer}' on bus {dev.bus} address {dev.address}."
    )

    dev.reset()
    dev.set_configuration()

    cfg = dev.get_active_configuration()

    intf = cfg.interfaces()[INTERFACE_NUMBER]

    ep_in = usb.util.find_descriptor(
        intf,
        custom_match=lambda ep: usb.util.endpoint_direction(
            ep.bEndpointAddress) == usb.util.ENDPOINT_IN)

    assert ep_in is not None

    print(f"Found endpoint in: {hex(ep_in.bEndpointAddress)}")

    ep_out = usb.util.find_descriptor(
        intf,
        custom_match=lambda ep: usb.util.endpoint_direction(
            ep.bEndpointAddress) == usb.util.ENDPOINT_OUT)

    assert ep_out is not None

    print(f"Found endpoint out: {hex(ep_out.bEndpointAddress)}")

    return dev, ep_in, ep_out


def connect_device(dev):
    usb.util.claim_interface(dev, INTERFACE_NUMBER)


def disconnect_device(dev):
    usb.util.release_interface(dev, INTERFACE_NUMBER)


if __name__ == "__main__":
    dev, ep_in, ep_out = find_device(0x27c6, 0x5110)
    connect_device(dev)

    try:
        print(
            construct_cmd_payload(
                0x81,
                bytes.fromhex(
                    "301160712c9d2cc91ce518fd00fd00fd03ba000080ca0006008400beb28600c5b98800b5ad8a009d958c0000be8e0000c5900000b59200009d940000af960000bf980000b69a0000a7d2000000d4000000d6000000d800000012000304d0000000700000007200785674003412200010402a0102002200012024003200800001045c000001560030485800020032000802660000027c000038820080152a0182032200012024001400800001045c00000156000c245800050032000802660000027c000038820080162a0108005c008000540000016200380464001000660000027c0001382a0108005c0000015200080054000001660000027c00013800e858"
                )))
    finally:
        disconnect_device(dev)
