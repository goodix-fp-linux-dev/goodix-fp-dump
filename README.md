`goodix_fp_dump` is a simple test program for the Goodix HTK32 Fingerprint reader present in the
Dell XPS13 9370.

# Test setup

In order to make the device accessible the user needs access to the USB device
node (e.g. `/dev/bus/usb/001/004`); so either run the program with sudo, or add
a udev rule.

Assuming that the user is in the `plugdev` group, something like the following
should work:

```
ACTION=="add", SUBSYSTEM=="usb", ATTRS{idVendor}=="27c6", ATTRS{idProduct}=="5385", MODE="0660", GROUP="plugdev" TAG+="uaccess"
```
# Goodix USB Fingerprint scanner protocol

The USB protocol seems to be quite simple at the packet level.

The general format of a packet is:

```
struct {
    uint8_t type;
    uint16_t payload_size; /* little-endian */
    uint8_t payload[]; /* conatains a checksum as last byte */
} goodif_fp_packet;
```

The communication takes place as follows:

1. The host sends a command packet with a type `ID` (an even number), and
   possibly some associated data and checksum.
   
   If the payload data and checksum do not fit in one 64 bytes packet then
   multiple packets are sent. Packets following the first one have the type
   equal to `ID + 1` to signal that they are **continuation** packets.

   Each output request is 64 bytes.

2. The device replies with a reply packet: `type: 0xb0, payload_size: 3` the
   payload contains the ID of the packet to which this is a reply and a status
   indicator, finally followed by a one-byte checksum.
   
   All input requests are 32768 bytes, but the number of actually transferred
   bytes depends on the packet type.

3. For some commands there is a response packet which starts with the ID of the
   command, followed by the payload size, and the payload data, and the
   checksum.
   
   If the payload data does not fit into 64 bytes, the data in the response
   packet would contain continuation packets.

   Note that the value of `payload_size` is the size of the useful data in
   response to a command plus one checksum byte, it does not include header
   fields and continuation bytes.

Image data seems to be encrypted.

## Packet structure

Packets are sent with bulk-out requests of 64 bytes on endpoint 0x03 of interface 1.

Replies are read with bulk-in requests of 32768 bytes on endpoint 0x81 of interface 1.

The [Kaitai struct](http://kaitai.io/) description of some single-packet
commands follows:

```
meta:
  id: goodix_fp
  endian: le
  license: CC0-1.0
seq:
  - id: header
    type: header
types:
  header:
    seq:
      - id: type
        type: u1
        enum: packet_type
      - id: payload_size
        type: u2
      - id: payload
        size: payload_size - 1
        type:
          switch-on: type
          cases:
            'packet_type::reply': payload_reply
            'packet_type::firmware_version': payload_firmware_version
      - id: checksum
        type: u1
  payload_reply:
    seq:
      - id: reply_to
        type: u1
        enum: packet_type
      - id: status
        type: u1
  payload_firmware_version:
    seq:
      - id: firmware_version
        type: str
        encoding: ascii
        terminator: 0
enums:
  packet_type:
    0xb0: reply
    0xa8: firmware_version
```

## Packet types

### Packet 0xb0

This is the generic reply, it is sent in response to every packet and precedes the actual response packet if there is any.

### Packet 0xa8

This returns the firmware version.

# Notes

[Ghidra](https://ghidra-sre.org/) project files for Windows drivers, with some
renamed functions and variables, are available here:
https://people.collabora.com/~ao2/ghidra-projects-2019-04-17.tar.gz
