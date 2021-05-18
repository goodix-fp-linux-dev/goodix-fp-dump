#!/usr/bin/python3

from struct import pack as encode
from struct import unpack as decode
from threading import Thread
from time import sleep, time

from usb.core import Device as UsbDevice
from usb.core import Endpoint, USBError, find
from usb.util import (ENDPOINT_IN, ENDPOINT_OUT, endpoint_direction,
                      find_descriptor)

# TODO Add some documentation


class MessagePack:
    def __init__(self,
                 payload: bytes = None,
                 flags: int = None,
                 length: int = None,
                 data: bytes = None):
        self.flags = self.length = self.data = None

        if payload is None:
            self.flags: int = flags
            self.length: int = length
            self.data: bytes = data

        else:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, MessagePack):
            flags = True if self.flags is None or obj.flags is None \
                else self.flags == obj.flags

            length = True if self.length is None or obj.length is None \
                else self.length == obj.length

            data = True if self.data is None or obj.data is None \
                else self.data == obj.data

            return flags and length and data

        return NotImplemented

    @property
    def payload(self) -> bytes:
        if self.flags is None or self.length is None or self.data is None:
            return None

        return bytes([self.flags]) + encode("<H", self.length) + bytes(
            [self.checksum]) + self.data

    @payload.setter
    def payload(self, payload: bytes):
        if payload is None:
            self.flags = self.length = self.data = None

        else:
            if payload[3] != sum(payload[0:3]) & 0xff:
                raise ValueError("Invalid payload checksum")

            length = decode("<H", payload[1:3])[0]
            self.flags, self.length, self.data = payload[0], length, payload[
                4:length + 4]

    @property
    def checksum(self) -> int:
        if self.flags is None or self.length is None or self.data is None:
            return None

        return sum(bytes([self.flags]) + encode("<H", self.length)) & 0xff


class MessageProtocol:
    def __init__(
            self,
            payload: bytes = None,
            cmd: int = None,  # TODO Use an instante on Command?
            length: int = None,
            data: bytes = None):
        self.cmd = self.length = self.data = None

        if payload is None:
            self.cmd: int = cmd
            self.length: int = length
            self.data: bytes = data

        else:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, MessageProtocol):
            cmd = True if self.cmd is None or obj.cmd is None \
                else self.cmd == obj.cmd

            length = True if self.length is None or obj.length is None \
                else self.length == obj.length

            data = True if self.data is None or obj.data is None \
                else self.data == obj.data

            return cmd and length and data

        return NotImplemented

    @property
    def payload(self) -> bytes:
        if self.cmd is None or self.length is None or self.data is None:
            return None

        return bytes([self.cmd]) + encode(
            "<H", self.length + 1) + self.data + bytes([self.checksum])

    @payload.setter
    def payload(self, payload: bytes):
        if payload is None:
            self.cmd = self.length = self.data = None

        else:
            length = decode("<H", payload[1:3])[0]
            if length <= len(payload[3:]) and 0xaa - sum(
                    payload[0:length + 2]) & 0xff != payload[length + 2]:
                raise ValueError("Invalid payload checksum")

            self.cmd, self.length, self.data = payload[0], length - 1, payload[
                3:length + 2]

    @property
    def checksum(self) -> int:
        if self.cmd is None or self.length is None or self.data is None:
            return None

        return 0xaa - sum(
            bytes([self.cmd]) + encode("<H", self.length + 1) +
            self.data) & 0xff


class Message:
    def __init__(
            self,
            payload: bytes = None,
            flags: int = None,  # TODO Remove flags
            cmd: int = None,  # TODO Same as MessageProtocol?
            data: bytes = None):
        self.message_pack, self.message_protocol = MessagePack(
        ), MessageProtocol()
        self.flags = self.cmd = self.data = None

        if payload is None:
            self.flags, self.cmd, self.data = flags, cmd, data

        else:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, Message):
            flags = True if self.flags is None or obj.flags is None \
                else self.flags == obj.flags

            cmd = True if self.cmd is None or obj.cmd is None \
                else self.cmd == obj.cmd

            data = True if self.data is None or obj.data is None \
                else self.data == obj.data

            return flags and cmd and data

        return NotImplemented

    @property
    def payload(self) -> bytes:
        return self.message_pack.payload

    @payload.setter
    def payload(self, payload: bytes):
        self.message_pack.payload = payload
        self.message_protocol.payload = self.message_pack.data

    @property
    def flags(self) -> int:
        return self.message_pack.flags

    @flags.setter
    def flags(self, flags: int):
        self.message_pack.flags = flags

    @property
    def cmd(self) -> int:
        return self.message_protocol.cmd

    @cmd.setter
    def cmd(self, cmd: int):
        self.message_protocol.cmd = cmd

    @property
    def data(self) -> bytes:
        return self.message_protocol.data

    @data.setter
    def data(self, data: bytes):
        if data is None:
            self.message_protocol.length = self.message_protocol.data = None
            self.message_pack.length = self.message_pack.data = None

        else:
            self.message_protocol.length, self.message_protocol.data = len(
                data), data

            if self.message_protocol.payload is None:
                self.message_pack.length = self.message_pack.data = None

            else:
                self.message_pack.length, self.message_pack.data = len(
                    self.message_protocol.payload
                ), self.message_protocol.payload


class Command:
    def __init__(self,
                 cmd: int = None,
                 cmd0: int = None,
                 cmd1: int = None,
                 cmd_lsb: bool = None):
        self.cmd0 = self.cmd1 = self.cmd_lsb = None

        if cmd is None:
            self.cmd0, self.cmd1 = cmd0, cmd1
            self.cmd_lsb: bool = cmd_lsb

        else:
            self.cmd = cmd

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, Command):
            cmd0 = True if self.cmd0 is None or obj.cmd0 is None \
                else self.cmd0 == obj.cmd0

            cmd1 = True if self.cmd1 is None or obj.cmd1 is None \
                else self.cmd1 == obj.cmd1

            cmd_lsb = True if self.cmd_lsb is None or obj.cmd_lsb is None \
                else self.cmd_lsb == obj.cmd_lsb

            return cmd0 and cmd1 and cmd_lsb

        return NotImplemented

    @property
    def cmd(self) -> int:
        if self.cmd0 is None or self.cmd1 is None or self.cmd_lsb is None:
            return None

        return self.cmd0 << 4 | self.cmd1 << 1 | (0x1 if self.cmd_lsb else 0x0)

    @cmd.setter
    def cmd(self, cmd: int):
        if cmd is None:
            self.cmd0 = self.cmd1 = self.cmd_lsb = None

        else:
            if cmd > 0xff:
                raise ValueError("cmd should be smaller or equal to 0xff")

            self._cmd0, self._cmd1, self.cmd_lsb = cmd >> 4, cmd >> 1 & 0x7, \
                cmd & 0x1 == 0x1

    @property
    def cmd0(self) -> int:
        return self._cmd0

    @cmd0.setter
    def cmd0(self, cmd0: int):
        if cmd0 is None:
            self._cmd0 = None

        else:
            if cmd0 > 0xf:
                raise ValueError("cmd0 should be smaller or equal to 0xf")

            self._cmd0 = cmd0

    @property
    def cmd1(self) -> int:
        return self._cmd1

    @cmd1.setter
    def cmd1(self, cmd1: int):
        if cmd1 is None:
            self._cmd1 = None

        else:
            if cmd1 > 0x7:
                raise ValueError("cmd1 should be smaller or equal to 0x7")

            self._cmd1 = cmd1


class Ack:
    def __init__(
        self,
        payload: bytes = None,
        acked_cmd: int = None,  # TODO Same as MessageProtocol?
        need_config: bool = None):  # TODO Rename to configured?
        self.acked_cmd = self.need_config = None

        if payload is None:
            self.acked_cmd: int = acked_cmd
            self.need_config: bool = need_config

        else:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, Ack):
            acked_cmd = True if self.acked_cmd is None \
                or obj.acked_cmd is None else self.acked_cmd == obj.acked_cmd

            need_config = True if self.need_config is None \
                or obj.need_config is None \
                    else self.need_config == obj.need_config

            return acked_cmd and need_config

        return NotImplemented

    @property
    def payload(self) -> bytes:
        if self.acked_cmd is None or self.need_config is None:
            return None

        return bytes([self.acked_cmd]) + (
            bytes.fromhex("03") if self.need_config else bytes.fromhex("01"))

    @payload.setter
    def payload(self, payload: bytes):
        if payload is None:
            self.acked_cmd = self.need_config = None

        else:
            if not payload[1] & 0x1:
                raise ValueError(
                    "Always true bool isn't True")  # Bad command ?

            self.acked_cmd, self.need_config = payload[
                0], payload[1] & 0x2 == 0x2


class Commands:
    ACK = Command(cmd0=0xb, cmd1=0x0, cmd_lsb=False)
    NOP = Command(cmd0=0x0, cmd1=0x0, cmd_lsb=False)
    ENABLE_CHIP = Command(cmd0=0x9, cmd1=0x3, cmd_lsb=False)
    FIRMWARE_VERSION = Command(cmd0=0xa, cmd1=0x4, cmd_lsb=False)
    PRESET_PSK_READ_R = Command(cmd0=0xe, cmd1=0x2, cmd_lsb=False)
    MCU_ERASE_APP = Command(cmd0=0xa, cmd1=0x2, cmd_lsb=False)


class Acks:
    ENABLE_CHIP = Ack(acked_cmd=Commands.ENABLE_CHIP.cmd)
    FIRMWARE_VERSION = Ack(acked_cmd=Commands.FIRMWARE_VERSION.cmd)
    PRESET_PSK_READ_R = Ack(acked_cmd=Commands.PRESET_PSK_READ_R.cmd)
    MCU_ERASE_APP = Ack(acked_cmd=Commands.MCU_ERASE_APP.cmd)


class Messages:
    NOP = Message(flags=0xa0,
                  cmd=Commands.NOP.cmd,
                  data=bytes.fromhex("00000000"))
    ENABLE_CHIP = Message(flags=0xa0, cmd=Commands.ENABLE_CHIP.cmd)
    FIRMWARE_VERSION = Message(flags=0xa0,
                               cmd=Commands.FIRMWARE_VERSION.cmd,
                               data=bytes.fromhex("0000"))
    PRESET_PSK_READ_R = Message(flags=0xa0,
                                cmd=Commands.PRESET_PSK_READ_R.cmd,
                                data=bytes.fromhex("030002bb00000000"))
    MCU_ERASE_APP = Message(flags=0xa0,
                            cmd=Commands.MCU_ERASE_APP.cmd,
                            data=bytes.fromhex("0000"))


class Device:
    def __init__(self, vendor: int, product: int, interface: int = 1):
        print(f"__init__({vendor}, {product}, {interface})")

        device: UsbDevice = find(idVendor=vendor, idProduct=product)

        if device is None:
            raise USBError("Device not found", -5, 19)

        print(f"Found '{device.product}' from '{device.manufacturer}' on bus \
{device.bus} address {device.address}.")

        device.set_configuration()
        cfg = device.get_active_configuration()
        interface = cfg.interfaces()[interface]

        self.ep_in: Endpoint = find_descriptor(
            interface,
            custom_match=lambda endpoint: endpoint_direction(
                endpoint.bEndpointAddress) == ENDPOINT_IN)
        if self.ep_in is None:
            raise USBError(
                "Endpoint in not found (The interface number might be wrong)",
                -5, 19)
        print(f"Found endpoint in: {hex(self.ep_in.bEndpointAddress)}")

        self.ep_out: Endpoint = find_descriptor(
            interface,
            custom_match=lambda endpoint: endpoint_direction(
                endpoint.bEndpointAddress) == ENDPOINT_OUT)
        if self.ep_out is None:
            raise USBError(
                "Endpoint out not found (The interface number might be wrong)",
                -5, 19)
        print(f"Found endpoint out: {hex(self.ep_out.bEndpointAddress)}")

        self.messages_pack: dict[float, MessagePack] = {}
        self.messages: dict[float, Message] = {}

        Thread(target=self._read_daemon, daemon=True).start()

    def _read_daemon(self):
        previous = 0
        while True:
            try:
                payload = bytes(self.ep_in.read(
                    8192, 0))  # TODO Change read size dynamically ?
                arrival = time()
            except USBError as error:
                if error.backend_error_code == -4:
                    break

                raise error

            print(f"read({payload})")

            if previous in self.messages_pack and len(
                    self.messages_pack[previous].data
            ) < self.messages_pack[previous].length:
                self.messages_pack[previous].payload += payload

            else:
                previous = arrival
                self.messages_pack[previous] = MessagePack(payload)

            print(self.messages_pack[previous].payload)

            if self.messages_pack[previous].flags == 0xa0 and len(
                    self.messages_pack[previous].data
            ) >= self.messages_pack[previous].length:
                self.messages[previous] = Message(
                    self.messages_pack[previous].payload)

                print(self.messages[previous].payload)

    def read_pack(self,
                  start: int = None,
                  condition=None,
                  count: int = 1,
                  timeout: int = 500) -> list[MessagePack]:
        if count is None:
            count = 0
        timeout = None if start is None or timeout is None or timeout == 0 \
            else start + timeout

        while True:
            result = list(
                map(
                    lambda key: self.messages_pack[key],
                    filter(
                        lambda key:
                        (True if start is None else key >= start and
                         (True if timeout is None else key <= timeout)) and
                        (True if condition is None else condition(
                            self.messages_pack[key])), self.messages_pack)))

            if len(result) >= count > 0:
                return result[0] if count == 1 else result[0:count]

            if time() > timeout:
                return result

            sleep(0.01)

    def read_message(self,
                     start: int = None,
                     condition=None,
                     count: int = 1,
                     timeout: int = 500) -> list[Message]:
        if count is None:
            count = 0
        timeout = None if start is None or timeout is None or timeout == 0 \
            else start + timeout

        while True:
            result = list(
                map(
                    lambda key: self.messages[key],
                    filter(
                        lambda key:
                        (True if start is None else key >= start and
                         (True if timeout is None else key <= timeout)) and
                        (True if condition is None else condition(
                            self.messages[key])), self.messages)))

            if len(result) >= count > 0:
                return result[0] if count == 1 else result[0:count]

            if time() > timeout:
                return result

            sleep(0.01)

    def write_pack(self, pack: MessagePack, timeout: int = 500):
        if timeout is None:
            timeout = 0

        payload = pack.payload

        print(f"write({payload})")

        if len(payload) % 64:
            payload += bytes.fromhex("00") * (64 - len(payload) % 64)

        for i in range(0, len(payload), 64):
            self.ep_out.write(payload[i:i + 64], timeout)

    def write_message(self, message: Message, timeout: int = 500):
        if timeout is None:
            timeout = 0

        payload = message.payload

        print(f"write({payload})")

        if len(payload) % 64:
            payload += bytes.fromhex("00") * (64 - len(payload) % 64)

        for i in range(0, len(payload), 64):
            self.ep_out.write(payload[i:i + 64], timeout)

    def nop(self):
        print("nop()")
        self.write_message(Messages.NOP)

    def enable_chip(self, enable=True):
        print(f"enable_chip({enable})")

        message = Messages.ENABLE_CHIP
        message.data = bytes.fromhex("0100") if enable else bytes.fromhex(
            "0000")

        start = time()
        self.write_message(message)

        print(
            self.read_message(
                start, lambda message: message.cmd == Commands.ACK.cmd and Ack(
                    message.data) == Acks.ENABLE_CHIP).payload)
        print("Ok")
