from copy import deepcopy
from struct import pack as encode
from struct import unpack as decode
from sys import version_info
from threading import Thread
from time import sleep, time
from typing import Callable, Dict, List, Literal, Optional
from usb.control import get_status

from usb.core import Endpoint, USBError, find
from usb.util import (CTRL_IN, CTRL_RECIPIENT_DEVICE, CTRL_TYPE_STANDARD,
                      DESC_TYPE_CONFIG, ENDPOINT_IN, ENDPOINT_OUT,
                      build_request_type, endpoint_direction, find_descriptor)

# TODO Add some documentation
# TODO Create a class with write and read method to be able to add SPI device

if version_info[0] != 3 or version_info[1] < 8:
    raise SystemError("You must use Python 3.8 or newer")


class Command:
    def __init__(self,
                 cmd: Optional[int] = None,
                 cmd0: Optional[int] = None,
                 cmd1: Optional[int] = None,
                 cmd_lsb: Optional[bool] = None) -> None:
        self.cmd0: Optional[int] = cmd0
        self.cmd1: Optional[int] = cmd1
        self.cmd_lsb: Optional[bool] = cmd_lsb

        if cmd is not None:
            self.cmd = cmd

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, Command):
            return (self.cmd0 is None or obj.cmd0 is None
                    or self.cmd0 == obj.cmd0) and (
                        self.cmd1 is None or obj.cmd1 is None or self.cmd1
                        == obj.cmd1) and (self.cmd_lsb is None
                                          or obj.cmd_lsb is None
                                          or self.cmd_lsb == obj.cmd_lsb)

        return NotImplemented

    def __len__(self) -> int:
        return 1

    @property
    def cmd(self) -> Optional[int]:
        return (None if self.cmd0 is None or self.cmd1 is None
                or self.cmd_lsb is None else self.cmd0 << 4 | self.cmd1 << 1 |
                (0x1 if self.cmd_lsb else 0x0))

    @cmd.setter
    def cmd(self, cmd: Optional[int]) -> None:
        if cmd is None:
            self.cmd0 = self.cmd1 = self.cmd_lsb = None

        else:
            if cmd > 0xff:
                raise ValueError("cmd should be smaller or equal to 0xff")

            self.cmd0, self.cmd1, self.cmd_lsb = (cmd >> 4, cmd >> 1 & 0x7,
                                                  cmd & 0x1 == 0x1)

    @property
    def cmd0(self) -> Optional[int]:
        return self._cmd0

    @cmd0.setter
    def cmd0(self, cmd0: Optional[int]) -> None:
        if cmd0 is None:
            self._cmd0 = None

        else:
            if cmd0 > 0xf:
                raise ValueError("cmd0 should be smaller or equal to 0xf")

            self._cmd0 = cmd0

    @property
    def cmd1(self) -> Optional[int]:
        return self._cmd1

    @cmd1.setter
    def cmd1(self, cmd1: Optional[int]) -> None:
        if cmd1 is None:
            self._cmd1 = None

        else:
            if cmd1 > 0x7:
                raise ValueError("cmd1 should be smaller or equal to 0x7")

            self._cmd1 = cmd1


class MessagePack:
    def __init__(self,
                 payload: Optional[bytes] = None,
                 flags: Optional[int] = None,
                 length: Optional[int] = None,
                 data: Optional[bytes] = None,
                 auto_length: Optional[bool] = None) -> None:
        self.flags: Optional[int] = flags
        self.length: Optional[int] = length
        self.data: Optional[bytes] = data
        self.auto_length: bool = (length is None
                                  if auto_length is None else auto_length)

        if payload is not None:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, MessagePack):
            return (self.flags is None or obj.flags is None
                    or self.flags == obj.flags) and (
                        self.length is None or obj.length is None
                        or self.length == obj.length) and (
                            self.data is None or obj.data is None
                            or self.data == obj.data)

        return NotImplemented

    def __len__(self) -> Optional[int]:
        return None if self.length is None else self.length + 4

    @property
    def length(self) -> Optional[int]:
        return (None if self.data is None else len(
            self.data)) if self.auto_length else self._length

    @length.setter
    def length(self, length: Optional[int]) -> None:
        self.auto_length = False
        self._length = length

    @property
    def payload(self) -> Optional[bytes]:
        return (None if self.flags is None or self.length is None
                or self.data is None else bytes([self.flags]) +
                encode("<H", self.length) + bytes([self.checksum]) + self.data)

    @payload.setter
    def payload(self, payload: Optional[bytes]) -> None:
        if payload is None:
            self.flags = self.length = self.data = None
        else:
            if payload[3] != sum(payload[0:3]) & 0xff:
                raise ValueError("Invalid payload checksum")

            self.flags, self.length, self.data = payload[0], decode(
                "<H",
                payload[1:3])[0], payload[4:decode("<H", payload[1:3])[0] + 4]

    @property
    def checksum(self) -> Optional[int]:
        return (None if self.flags is None or self.length is None
                or self.data is None else
                sum(bytes([self.flags]) + encode("<H", self.length)) & 0xff)


class MessageProtocol:
    def __init__(self,
                 payload: Optional[bytes] = None,
                 command: Optional[Command] = None,
                 length: Optional[int] = None,
                 data: Optional[bytes] = None,
                 auto_length: Optional[bool] = None) -> None:
        self.command: Command = Command() if command is None else command
        self.length: Optional[int] = length
        self.data: Optional[bytes] = data
        self.auto_length: bool = (length is None
                                  if auto_length is None else auto_length)

        if payload is not None:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, MessageProtocol):
            return (self.command == obj.command) and (
                self.length is None or obj.length is None or self.length
                == obj.length) and (self.data is None or obj.data is None
                                    or self.data == obj.data)

        return NotImplemented

    def __len__(self) -> Optional[int]:
        return None if self.length is None else self.length + len(
            self.command) + 3

    @property
    def length(self) -> Optional[int]:
        return (None if self.data is None else len(
            self.data)) if self.auto_length else self._length

    @length.setter
    def length(self, length: Optional[int]) -> None:
        self.auto_length = False
        self._length = length

    @property
    def payload(self) -> Optional[bytes]:
        return (None if self.command.cmd is None or self.length is None
                or self.data is None else bytes([self.command.cmd]) +
                encode("<H", self.length + 1) + self.data +
                bytes([self.checksum]))

    @payload.setter
    def payload(self, payload: Optional[bytes]) -> None:
        if payload is None:
            self.command.cmd = self.length = self.data = None

        else:
            if decode("<H", payload[1:3])[0] <= len(
                    payload[3:]) and 0xaa - sum(
                        payload[0:decode("<H", payload[1:3])[0] + 2]
                    ) & 0xff != payload[decode("<H", payload[1:3])[0] + 2]:
                raise ValueError("Invalid payload checksum")

            self.command.cmd, self.length, self.data = payload[0], decode(
                "<H",
                payload[1:3])[0] - 1, payload[3:decode("<H", payload[1:3])[0] +
                                              2]

    @property
    def checksum(self) -> Optional[int]:
        return (None if self.command.cmd is None or self.length is None
                or self.data is None else 0xaa - sum(
                    bytes([self.command.cmd]) + encode("<H", self.length + 1) +
                    self.data)
                & 0xff)


class Message:
    def __init__(self,
                 payload: Optional[bytes] = None,
                 message_protocol: Optional[MessageProtocol] = None) -> None:
        self._message_pack: MessagePack = MessagePack(
            flags=FLAGS_MESSAGE_PROTOCOL)
        self.message_protocol: MessageProtocol = MessageProtocol(
        ) if message_protocol is None else message_protocol

        if payload is not None:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, Message):
            self._message_pack.data = None
            return (self._message_pack
                    == obj._message_pack) and (self.message_protocol
                                               == obj.message_protocol)

        return NotImplemented

    def __len__(self) -> Optional[int]:
        self._message_pack.data = self.message_protocol.payload
        return len(self._message_pack)

    @property
    def payload(self) -> Optional[bytes]:
        self._message_pack.data = self.message_protocol.payload
        return self._message_pack.payload

    @payload.setter
    def payload(self, payload: Optional[bytes]) -> None:
        self._message_pack.payload = payload
        if len(self._message_pack.data) != self._message_pack.length:
            raise ValueError("Invalid data length")

        self._message_pack.auto_length = True
        self.message_protocol.payload = self._message_pack.data


class Ack:
    def __init__(self,
                 payload: Optional[bytes] = None,
                 command: Optional[Command] = None,
                 configured: Optional[bool] = None) -> None:
        self.command: Command = Command() if command is None else command
        self.configured: Optional[bool] = configured

        if payload is not None:
            self.payload = payload

    def __eq__(self, obj: object) -> bool:
        if isinstance(obj, Ack):
            return (self.command
                    == obj.command) and (self.configured is None
                                         or obj.configured is None
                                         or self.configured == obj.configured)

        return NotImplemented

    def __len__(self) -> int:
        return len(self.command) + 1

    @property
    def payload(self) -> Optional[bytes]:
        return (
            None if self.command.cmd is None or self.configured is None else
            bytes([self.command.cmd]) +
            (bytes.fromhex("01") if self.configured else bytes.fromhex("03")))

    @payload.setter
    def payload(self, payload: Optional[bytes]) -> None:
        if payload is None:
            self.command.cmd = self.configured = None

        else:
            if not payload[1] & 0x1:
                raise ValueError("Always true bool isn't True")

            self.command.cmd, self.configured = payload[
                0], payload[1] & 0x2 != 0x2


FLAGS_MESSAGE_PROTOCOL: Literal[0xa0] = 0xa0
FLAGS_TRANSPORT_LAYER_SECURITY: Literal[0xb0] = 0xb0

COMMAND_NOP: Command = Command(cmd0=0x0, cmd1=0x0, cmd_lsb=False)
COMMAND_MCU_GET_IMAGE: Command = Command(cmd0=0x2, cmd1=0x0, cmd_lsb=False)
COMMAND_ENABLE_CHIP: Command = Command(cmd0=0x9, cmd1=0x3, cmd_lsb=False)
COMMAND_RESET: Command = Command(cmd0=0xa, cmd1=0x1, cmd_lsb=False)
COMMAND_MCU_ERASE_APP: Command = Command(cmd0=0xa, cmd1=0x2, cmd_lsb=False)
COMMAND_FIRMWARE_VERSION: Command = Command(cmd0=0xa, cmd1=0x4, cmd_lsb=False)
COMMAND_ACK: Command = Command(cmd0=0xb, cmd1=0x0, cmd_lsb=False)
COMMAND_PRESET_PSK_WRITE_R: Command = Command(cmd0=0xe,
                                              cmd1=0x0,
                                              cmd_lsb=False)
COMMAND_PRESET_PSK_READ_R: Command = Command(cmd0=0xe, cmd1=0x2, cmd_lsb=False)
COMMAND_WRITE_FIRMWARE: Command = Command(cmd0=0xf, cmd1=0x0, cmd_lsb=False)
COMMAND_READ_FIRMWARE: Command = Command(cmd0=0xf, cmd1=0x1, cmd_lsb=False)
COMMAND_UPDATE_FIRMWARE: Command = Command(cmd0=0xf, cmd1=0x2, cmd_lsb=False)

ACK_NOP: Ack = Ack(command=COMMAND_NOP)
ACK_MCU_GET_IMAGE: Ack = Ack(command=COMMAND_MCU_GET_IMAGE)
ACK_ENABLE_CHIP: Ack = Ack(command=COMMAND_ENABLE_CHIP)
ACK_RESET: Ack = Ack(command=COMMAND_RESET)
ACK_MCU_ERASE_APP: Ack = Ack(command=COMMAND_MCU_ERASE_APP)
ACK_FIRMWARE_VERSION: Ack = Ack(command=COMMAND_FIRMWARE_VERSION)
ACK_PRESET_PSK_WRITE_R: Ack = Ack(command=COMMAND_PRESET_PSK_WRITE_R)
ACK_PRESET_PSK_READ_R: Ack = Ack(command=COMMAND_PRESET_PSK_READ_R)
ACK_WRITE_FIRMWARE: Ack = Ack(command=COMMAND_WRITE_FIRMWARE)
ACK_READ_FIRMWARE: Ack = Ack(command=COMMAND_READ_FIRMWARE)
ACK_UPDATE_FIRMWARE: Ack = Ack(command=COMMAND_UPDATE_FIRMWARE)

MESSAGE_PROTOCOL_NOP: MessageProtocol = MessageProtocol(
    command=COMMAND_NOP, data=bytes.fromhex("00000000"))
MESSAGE_PROTOCOL_MCU_GET_IMAGE: MessageProtocol = MessageProtocol(
    command=COMMAND_MCU_GET_IMAGE, data=bytes.fromhex("0100"))
MESSAGE_PROTOCOL_ENABLE_CHIP: MessageProtocol = MessageProtocol(
    command=COMMAND_ENABLE_CHIP)
MESSAGE_PROTOCOL_RESET: MessageProtocol = MessageProtocol(
    command=COMMAND_RESET)
MESSAGE_PROTOCOL_MCU_ERASE_APP: MessageProtocol = MessageProtocol(
    command=COMMAND_MCU_ERASE_APP, data=bytes.fromhex("0000"))
MESSAGE_PROTOCOL_FIRMWARE_VERSION: MessageProtocol = MessageProtocol(
    command=COMMAND_FIRMWARE_VERSION, data=bytes.fromhex("0000"))
MESSAGE_PROTOCOL_PRESET_PSK_WRITE_R: MessageProtocol = MessageProtocol(
    command=COMMAND_PRESET_PSK_WRITE_R)
MESSAGE_PROTOCOL_PRESET_PSK_READ_R: MessageProtocol = MessageProtocol(
    command=COMMAND_PRESET_PSK_READ_R)
MESSAGE_PROTOCOL_WRITE_FIRMWARE: MessageProtocol = MessageProtocol(
    command=COMMAND_WRITE_FIRMWARE)
MESSAGE_PROTOCOL_READ_FIRMWARE: MessageProtocol = MessageProtocol(
    command=COMMAND_READ_FIRMWARE)
MESSAGE_PROTOCOL_UPDATE_FIRMWARE: MessageProtocol = MessageProtocol(
    command=COMMAND_UPDATE_FIRMWARE)

MESSAGE_NOP: Message = Message(message_protocol=MESSAGE_PROTOCOL_NOP)
MESSAGE_MCU_GET_IMAGE = Message(
    message_protocol=MESSAGE_PROTOCOL_MCU_GET_IMAGE)
MESSAGE_ENABLE_CHIP: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_ENABLE_CHIP)
MESSAGE_RESET: Message = Message(message_protocol=MESSAGE_PROTOCOL_RESET)
MESSAGE_MCU_ERASE_APP: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_MCU_ERASE_APP)
MESSAGE_FIRMWARE_VERSION: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_FIRMWARE_VERSION)
MESSAGE_PRESET_PSK_WRITE_R: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_PRESET_PSK_WRITE_R)
MESSAGE_PRESET_PSK_READ_R: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_PRESET_PSK_READ_R)
MESSAGE_WRITE_FIRMWARE: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_WRITE_FIRMWARE)
MESSAGE_READ_FIRMWARE: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_READ_FIRMWARE)
MESSAGE_UPDATE_FIRMWARE: Message = Message(
    message_protocol=MESSAGE_PROTOCOL_UPDATE_FIRMWARE)


class Device:
    def __init__(self,
                 product: int,
                 interface: int,
                 timeout: float = 5) -> None:
        print(f"__init__({hex(product)}, {interface})")

        timeout = None if timeout == 0 else time() + timeout

        self._product: int = product

        while True:
            device = find(idVendor=0x27c6, idProduct=self._product)

            if device is not None:
                try:
                    get_status(device)
                    break

                except USBError as error:
                    if (error.backend_error_code != -1
                            and error.backend_error_code != -4):
                        raise error

            if timeout is not None and time() > timeout:
                if device is None:
                    raise USBError("Device not found", -5, 19)

                raise USBError("Invalid device state", -12, 131)

            sleep(0.01)

        device.ctrl_transfer(
            build_request_type(CTRL_IN, CTRL_TYPE_STANDARD,
                               CTRL_RECIPIENT_DEVICE),
            6,
            DESC_TYPE_CONFIG << 8,
            data_or_wLength=255
        )  # Not necessary but premit to the Goodix plugin for Wireshark to work

        print(f"Found \"{device.product}\" "
              f"from \"{device.manufacturer}\" "
              f"on bus \"{device.bus}\" "
              f"address \"{device.address}\".")

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

        self.messages_pack: Dict[float, MessagePack] = {}
        self.messages: Dict[float, Message] = {}

        self._deamon: Thread = Thread(target=self._read_daemon, daemon=True)

        self._deamon.start()

    def _read_daemon(self) -> None:
        previous = 0
        while True:
            try:
                payload = bytes(self.ep_in.read(8192, 0))
                arrival = time()
            except USBError as error:
                if (error.backend_error_code == -1
                        or error.backend_error_code == -4):
                    print("Stopped reading")
                    break

                raise error

            if previous in self.messages_pack and len(
                    self.messages_pack[previous].data
            ) < self.messages_pack[previous].length:
                self.messages_pack[previous].payload += payload

            else:
                previous = arrival
                self.messages_pack[previous] = MessagePack(payload)

            if self.messages_pack[
                    previous].flags == FLAGS_MESSAGE_PROTOCOL and len(
                        self.messages_pack[previous].data
                    ) >= self.messages_pack[previous].length:
                self.messages[previous] = Message(
                    self.messages_pack[previous].payload)

    def wait_disconnect(self) -> None:
        while self._deamon.is_alive():
            sleep(0.01)

    def write_message_pack(self,
                           pack: MessagePack,
                           timeout: Optional[float] = 1) -> None:
        timeout = 0 if timeout is None else timeout

        payload = pack.payload

        if len(payload) % 64:
            payload += bytes.fromhex("00") * (64 - len(payload) % 64)

        for i in range(0, len(payload), 64):
            self.ep_out.write(payload[i:i + 64], round(timeout * 1000))

    def write_message(self,
                      message: Message,
                      timeout: Optional[float] = 1) -> None:
        timeout = 0 if timeout is None else timeout

        payload = message.payload

        if len(payload) % 64:
            payload += bytes.fromhex("00") * (64 - len(payload) % 64)

        for i in range(0, len(payload), 64):
            self.ep_out.write(payload[i:i + 64], round(timeout * 1000))

    def read_message_pack(self,
                          start: Optional[float] = None,
                          condition: Optional[Callable[[MessagePack],
                                                       bool]] = None,
                          count: Optional[int] = 1,
                          timeout: Optional[float] = 1) -> List[MessagePack]:
        count = 0 if count is None else count
        timeout = (None if start is None or timeout is None or timeout == 0
                   else start + timeout)

        while True:
            result = list(
                map(
                    lambda key: self.messages_pack[key],
                    filter(
                        lambda key: (start is None or
                                     (key >= start and
                                      (timeout is None or key <= timeout))) and
                        (condition is None or condition(self.messages_pack[
                            key])), self.messages_pack)))

            if len(result) >= count > 0:
                return result[0:count]

            if time() > timeout:
                return result

            sleep(0.01)

    def read_message(self,
                     start: Optional[float] = None,
                     condition: Optional[Callable[[Message], bool]] = None,
                     count: Optional[int] = 1,
                     timeout: Optional[float] = 1) -> List[Message]:
        count = 0 if count is None else count
        timeout = (None if start is None or timeout is None or timeout == 0
                   else start + timeout)

        while True:
            result = list(
                map(
                    lambda key: self.messages[key],
                    filter(
                        lambda key: (start is None or
                                     (key >= start and
                                      (timeout is None or key <= timeout))) and
                        (condition is None or condition(self.messages[key])),
                        self.messages)))

            if len(result) >= count > 0:
                return result[0:count]

            if time() > timeout:
                return result

            sleep(0.01)

    def setup(self):
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("a203000114f0"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("82060000000004001e"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("a60300000001"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("a203000114f0"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("700300140023"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("800600002002780b7f"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("800600003602b90033"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("800600003802b70033"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("800600003a02b70031"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex(
                    "900101701160712c9d2cc91ce518fd00fd00fd03ba000180ca000400840015b3860000c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000b6980000009a000000d2000000d4000000d6000000d800000050000105d0000000700000007200785674003412200010402a0102042200012024003200800001005c008000560004205800030232000c02660003007c000058820080152a0182032200012024001400800001005c000001560004205800030232000c02660003007c0000588200801f2a0108005c008000540010016200040364001900660003007c0001582a0108005c0000015200080054000001660003007c00015800892e6f"
                ))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("9403006400af"))))
        sleep(0.1)
        self.write_message(
            Message(
                message_protocol=MessageProtocol(bytes.fromhex("ae020055a5"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("360f000d01afafbfbfa4a4b8b8a8a8b7b705"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("360f000d0180af80c080a480b780a780b630"))))
        sleep(0.1)
        self.write_message(
            Message(message_protocol=MessageProtocol(
                bytes.fromhex("82060000820002009e"))))
        sleep(0.1)

    def nop(self) -> None:
        print("nop()")

        start = time()
        self.write_message(MESSAGE_NOP)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_NOP,
            timeout=0.1)

        if message:
            print("Got ack reply, device may use an old firmware version")

    def mcu_get_image(self) -> bytes:
        print("mcu_get_image()")

        start = time()
        self.write_message(MESSAGE_MCU_GET_IMAGE)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_MCU_GET_IMAGE)

        if not message:
            raise SystemError("Failed to get MCU image (No ack)")

        message = self.read_message_pack(
            start,
            lambda message: message.flags >= FLAGS_TRANSPORT_LAYER_SECURITY and
            len(message.data) >= message.length)

        if not message:
            raise SystemError("Failed to get MCU image (No reply)")

        return message[0].data

    def enable_chip(self, enable: bool = True) -> None:
        print(f"enable_chip(enable={enable})")

        message = deepcopy(MESSAGE_ENABLE_CHIP)
        message.message_protocol.data = bytes.fromhex(
            "0100") if enable else bytes.fromhex("0000")

        start = time()
        self.write_message(message)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_ENABLE_CHIP)

        if not message:
            raise SystemError("Failed to enable chip (No ack)")

    def reset(self,
              reset_sensor: bool = True,
              soft_reset_mcu: bool = False) -> Optional[int]:
        print(f"reset(reset_sensor={reset_sensor}, "
              f"soft_reset_mcu={soft_reset_mcu})")

        message = deepcopy(MESSAGE_RESET)
        message.message_protocol.data = bytes([
            (0x1 if reset_sensor else 0x0) | (0x2 if soft_reset_mcu else 0x0)
        ]) + bytes.fromhex("14")

        start = time()
        self.write_message(message)

        message = self.read_message(
            start, lambda message: message.message_protocol.command ==
            COMMAND_ACK and Ack(message.message_protocol.data) == ACK_RESET)

        if not message:
            raise SystemError("Failed to reset device (No ack)")

        if soft_reset_mcu:
            return None

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_RESET)

        if not message:
            raise SystemError("Failed to reset device (No reply)")

        data = message[0].message_protocol.data
        if len(data) != 3:
            raise SystemError("Failed to reset device (Invalid reply length)")

        if data[0] != 1:
            raise SystemError("Failed to reset device (Invalid reply)")

        return decode("<H", data[1:2])

    def mcu_erase_app(self) -> None:
        print("mcu_erase_app()")

        start = time()
        self.write_message(MESSAGE_MCU_ERASE_APP)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_MCU_ERASE_APP)

        if not message:
            raise SystemError("Failed to erase MCU app (No ack)")

    def firmware_version(self) -> str:
        print("firmware_version()")

        start = time()
        self.write_message(MESSAGE_FIRMWARE_VERSION)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_FIRMWARE_VERSION)

        if not message:
            raise SystemError("Failed to get firmware version (No ack)")

        message = self.read_message(
            start, lambda message: message.message_protocol.command ==
            COMMAND_FIRMWARE_VERSION)

        if not message:
            raise SystemError("Failed to get firmware version (No reply)")

        return message[0].message_protocol.data.decode().rstrip("\0")

    def preset_psk_write_r(self, address: int, length: int,
                           data: bytes) -> None:
        print(f"preset_psk_write_r(address={address}, length={length}, "
              f"data={data})")

        message = deepcopy(MESSAGE_PRESET_PSK_WRITE_R)
        message.message_protocol.data = encode("<I", address) + encode(
            "<I", length) + data

        start = time()
        self.write_message(message)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_PRESET_PSK_WRITE_R)

        if not message:
            raise SystemError("Failed to write PSK R (No ack)")

        message = self.read_message(
            start, lambda message: message.message_protocol.command ==
            COMMAND_PRESET_PSK_WRITE_R)

        if not message:
            raise SystemError("Failed to write PSK R (No reply)")

        data = message[0].message_protocol.data
        if len(data) != 2:
            raise SystemError("Failed to write PSK R (Invalid reply length)")

        if data != bytes.fromhex("0003"):
            raise SystemError("Failed to write PSK R (Invalid reply)")

    def preset_psk_read_r(self, address: int) -> bytes:
        print(f"preset_psk_read_r(address={address})")

        message = deepcopy(MESSAGE_PRESET_PSK_READ_R)
        message.message_protocol.data = encode("<I", address) + encode("<I", 0)

        start = time()
        self.write_message(message)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_PRESET_PSK_READ_R)

        if not message:
            raise SystemError("Failed to read PSK R (No ack)")

        message = self.read_message(
            start, lambda message: message.message_protocol.command ==
            COMMAND_PRESET_PSK_READ_R)

        if not message:
            raise SystemError("Failed to read PSK R (No reply)")

        return message[0].message_protocol.data

    def write_firmware(self, offset: int, data: bytes) -> None:
        print(f"write_firmware(offset={hex(offset)}, data={data})")

        length = len(data)
        if length > 1008:
            raise ValueError("data length must be smaller or equal to 1008")

        message = deepcopy(MESSAGE_WRITE_FIRMWARE)
        message.message_protocol.data = encode("<I", offset) + encode(
            "<I", length) + data

        start = time()
        self.write_message(message)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_WRITE_FIRMWARE)

        if not message:
            raise SystemError("Failed to write firmware (No ack)")

        message = self.read_message(
            start, lambda message: message.message_protocol.command ==
            COMMAND_WRITE_FIRMWARE)

        if not message:
            raise SystemError("Failed to write firmware (No reply)")

        data = message[0].message_protocol.data
        if len(data) != 2:
            raise SystemError(
                "Failed to write firmware (Invalid reply length)")

        if data[0] != 1:
            raise SystemError("Failed to write firmware (Invalid reply)")

    def read_firmware(self, offset: int, length: int) -> bytes:
        print(f"read_firmware(offset={hex(offset)}, length={length})")

        if length > 1024:
            raise ValueError("length must be smaller or equal to 1024")

        message = deepcopy(MESSAGE_READ_FIRMWARE)
        message.message_protocol.data = encode("<I", offset) + encode(
            "<I", length)

        start = time()
        self.write_message(message)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_READ_FIRMWARE)

        if not message:
            raise SystemError("Failed to read firmware (No ack)")

        message = self.read_message(
            start, lambda message: message.message_protocol.command ==
            COMMAND_READ_FIRMWARE)

        if not message:
            raise SystemError("Failed to read firmware (No reply)")

        data = message[0].message_protocol.data
        if len(data) != length:
            raise SystemError("Failed to read firmware (Invalid reply length)")

        return data

    def update_firmware(self, offset: int, length: int, data: bytes) -> None:
        print(f"update_firmware(offset={hex(offset)}, length={length}, "
              f"data={data})")

        message = deepcopy(MESSAGE_UPDATE_FIRMWARE)
        message.message_protocol.data = encode("<I", offset) + encode(
            "<I", length) + data

        start = time()
        self.write_message(message)

        message = self.read_message(
            start,
            lambda message: message.message_protocol.command == COMMAND_ACK and
            Ack(message.message_protocol.data) == ACK_UPDATE_FIRMWARE)

        if not message:
            raise SystemError("Failed to update firmware (No ack)")

        message = self.read_message(
            start, lambda message: message.message_protocol.command ==
            COMMAND_UPDATE_FIRMWARE)

        if not message:
            raise SystemError("Failed to update firmware (No reply)")

        data = message[0].message_protocol.data
        if len(data) != 2:
            raise SystemError(
                "Failed to update firmware (Invalid reply length)")

        if data[0] != 1:
            raise SystemError("Failed to update firmware (Invalid reply)")
