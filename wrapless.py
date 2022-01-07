from protocol import Protocol
from typing import Optional
import logging
import struct
from dataclasses import dataclass

from usb.core import USBTimeoutError
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from crccheck.crc import Crc32Mpeg2

USB_CHUNK_SIZE = 0x40


@dataclass
class Message:
    _category: int
    _command: int
    _payload: bytes

    @property
    def category(self) -> int:
        return self._category

    @category.setter
    def category(self, category) -> None:
        assert category <= 0xF
        self._category = category

    @property
    def command(self) -> int:
        return self._command

    @command.setter
    def command(self, command) -> None:
        assert command <= 0x7
        self._command = command

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, payload) -> None:
        assert len(payload) <= 0xFFFF
        self._payload = payload


class Device:
    def __init__(self, product: int, protocol, timeout: Optional[float] = 5) -> None:
        logging.debug(f"__init__({product}, {protocol}, {timeout})")

        self.protocol: Protocol = protocol(0x27C6, product, timeout)
        self.gtls_context: Optional[GTLSContext] = None

        # FIXME Empty device reply buffer
        # (Current patch while waiting for a fix)
        self._empty_buffer()

    def _empty_buffer(self) -> None:
        logging.debug("_empty_buffer()")

        try:
            while True:
                self.protocol.read(timeout=0.1)

        except USBTimeoutError as error:
            if error.backend_error_code == -7:
                return

            raise error

    def _recv_next_chunk(self, timeout: float) -> bytes:
        for _ in range(10):
            chunk = self.protocol.read(USB_CHUNK_SIZE, timeout=timeout)
            if chunk:
                return chunk
        raise Exception("Too many empty reads")

    def _recv_message_from_device(
        self,
        timeout: float,
    ) -> Message:
        data = self._recv_next_chunk(timeout)
        logging.debug(f"Received chunk from device: {data.hex(' ')}")

        command_byte = data[0]
        message_size = struct.unpack("<H", data[1:3])[0]

        while len(data) - 1 < message_size:
            chunk = self._recv_next_chunk(timeout)
            logging.debug(f"Received chunk from device: {chunk.hex(' ')}")

            contd_command_byte = chunk[0]
            if contd_command_byte & 1 == 0 or contd_command_byte & 0xFE != command_byte:
                raise Exception("Wrong continued chunk")

            data += chunk[1:]

        category = command_byte >> 4
        command = (command_byte & 0xF) >> 1
        data = data[: message_size + 3]

        msg_checksum = data[-1]
        data = data[:-1]
        if msg_checksum != 0x88:
            checksum = 0xAA - sum(data) & 0xFF
            if msg_checksum != checksum:
                raise Exception(
                    f"Wrong checksum, "
                    f"expected: {hex(checksum)}, received: {hex(msg_checksum)}"
                )

        payload = data[3:]

        message = Message(category, command, payload)

        logging.info(f"Received message from device: {message}")

        return message

    def _check_ack(self, command_byte: int, timeout: float) -> None:
        message = self._recv_message_from_device(timeout)

        if message.category != 0xB:
            raise Exception("Not an ACK message")

        if message.command != 0:
            raise Exception("ACK should not have commands")

        if command_byte != message.payload[0]:
            raise Exception("ACK wrong command")

        logging.info(f"Received ACK for {hex(command_byte)}")

    def _send_message_to_device(
        self,
        message: Message,
        use_checksum: bool,
        ack_timeout: float,
    ) -> None:
        command_byte = message.category << 4 | message.command << 1

        data = struct.pack("<B", command_byte)
        data += struct.pack("<H", len(message.payload) + 1)
        data += message.payload
        checksum = 0xAA - sum(data) & 0xFF if use_checksum else 0x88
        data += struct.pack("<B", checksum)

        logging.info(f"Sending message: {data.hex(' ')}")

        is_first = True
        while data:
            if is_first:
                chunk = data[:USB_CHUNK_SIZE]
                data = data[USB_CHUNK_SIZE:]
                is_first = False
            else:
                chunk = struct.pack("<B", command_byte | 1)
                chunk += data[: USB_CHUNK_SIZE - 1]
                data = data[USB_CHUNK_SIZE - 1 :]
            assert len(chunk) <= USB_CHUNK_SIZE

            logging.debug(f"Sending chunk: {chunk.hex(' ')}")
            self.protocol.write(chunk)

        self._check_ack(command_byte, ack_timeout)

    def ping(self) -> None:
        logging.debug("ping()")
        self._send_message_to_device(Message(0, 0, b"\x00\x00"), True, 0.5)

    def read_firmware_version(self) -> str:
        logging.debug("firmware_version()")
        self._send_message_to_device(Message(0xA, 4, b"\x00\x00"), True, 0.5)

        message = self._recv_message_from_device(2)
        if message.category != 0xA or message.command != 4:
            raise Exception("Not a firmware version reply")

        return message.payload.split(b"\x00")[0].decode()

    def _production_read(self, read_type: int) -> bytes:
        request = Message(0xE, 2, struct.pack("<L", read_type))
        self._send_message_to_device(request, True, 0.5)

        reply = self._recv_message_from_device(1)
        if reply.category != 0xE or reply.command != 2:
            raise Exception("Not a production read reply")

        payload = reply.payload

        if payload[0] != 0:
            raise Exception("Production read MCU failed")
        payload = payload[1:]

        msg_read_type = struct.unpack("<L", payload[:4])[0]
        payload = payload[4:]
        if read_type != msg_read_type:
            raise Exception(
                f"Wrong read type in reply, "
                f"expected: {hex(read_type)}, received: {hex(msg_read_type)}"
            )

        payload_size = struct.unpack("<L", payload[:4])[0]
        payload = payload[4:]
        if payload_size != len(payload):
            raise Exception(
                f"Payload does not match reported size: "
                f"{payload_size} != {len(payload)}"
            )

        return payload

    def _production_write(self, data_type: int, data: bytes) -> None:
        payload = struct.pack("<L", data_type)
        payload += struct.pack("<L", len(data))  # Header size excluded
        payload += data

        self._send_message_to_device(Message(0xE, 1, payload), True, 0.5)

        reply = self._recv_message_from_device(1)
        if reply.category != 0xE or reply.command != 1:
            raise Exception("Not a production write reply")

        if reply.payload[0] != 0:
            raise Exception("Production write MCU failed")

    def _recv_mcu(self, read_type) -> bytes:
        logging.debug("recv_mcu()")

        message = self._recv_message_from_device(2)
        if message.category != 0xD or message.command != 1:
            raise Exception("Not a GTLS handshake message")

        payload = message.payload

        msg_read_type = struct.unpack("<L", payload[:4])[0]
        if read_type != msg_read_type:
            raise Exception(
                f"Wrong read type in reply, "
                f"expected: {hex(read_type)}, received: {hex(msg_read_type)}"
            )

        payload_size = struct.unpack("<L", payload[4:8])[0]
        if payload_size != len(payload):
            raise Exception(
                f"Payload does not match reported size: "
                f"{payload_size} != {len(payload)}"
            )

        return payload[8:]

    def _send_mcu(self, data_type, data: bytes) -> None:
        logging.debug("send_mcu()")

        payload = struct.pack("<L", data_type)
        payload += struct.pack("<L", len(data) + 8)  # Header size included
        payload += data

        self._send_message_to_device(Message(0xD, 1, payload), True, 0.5)

    def read_sealed_psk(self) -> bytes:
        logging.debug("read_sealed_psk()")
        return self._production_read(0xB001)

    def write_sealed_psk(self, sealed_psk: bytes) -> None:
        logging.debug("writing_sealed_psk()")
        return self._production_write(0xB001, sealed_psk)

    def write_psk_white_box(self, psk_white_box: bytes) -> None:
        logging.debug("write_psk_white_box()")
        self._production_write(0xB002, psk_white_box)

    def read_psk_hash(self) -> bytes:
        logging.debug("read_psk_hash()")
        return self._production_read(0xB003)

    def establish_gtls_connection(self, psk) -> None:
        logging.debug("establish_gtls_connection()")
        self.gtls_context = GTLSContext(psk, self)
        self.gtls_context.establish_connection()

    def read_sensor_register(
        self, register: int, read_size: int, timeout: float
    ) -> bytes:
        request = b"\x00"
        request += struct.pack("<H", register)
        request += struct.pack("<H", read_size)

        self._send_message_to_device(Message(0x8, 0x1, request), True, 0.5)

        reply = self._recv_message_from_device(timeout)
        if reply.category != 0x8 or reply.command != 0x1:
            raise Exception("Not a register read message")

        return reply.payload

    def read_otp(self, timeout: float) -> bytes:
        self._send_message_to_device(Message(0xA, 0x3, b"\x00\x00"), True, 0.5)

        reply = self._recv_message_from_device(timeout)
        if reply.category != 0xA or reply.command != 0x3:
            raise Exception("Not a register read message")

        return reply.payload


class GTLSContext:
    def __init__(self, psk: bytes, device: Device):
        self.state = 0
        self.client_random: Optional[bytes] = None
        self.server_random: Optional[bytes] = None
        self.client_identity: Optional[bytes] = None
        self.server_identity: Optional[bytes] = None
        self.symmetric_key: Optional[bytes] = None
        self.symmetric_iv: Optional[bytes] = None
        self.hmac_key: Optional[bytes] = None
        self.hmac_client_counter_init: Optional[int] = None
        self.hmac_server_counter_init: Optional[int] = None
        self.hmac_client_counter: Optional[int] = None
        self.hmac_server_counter: Optional[int] = None
        self.psk = psk
        self.device = device

    def _client_hello_step(self) -> None:
        if self.state >= 2:
            raise Exception(f"Cannot send client hello, state: {self.state}")

        self.client_random = get_random_bytes(0x20)
        logging.debug(f"client_random: {self.client_random.hex(' ')}")

        self.device._send_mcu(0xFF01, self.client_random)
        self.state = 2

    def _server_identity_step(self) -> None:
        if self.state != 2:
            raise Exception(f"Cannot receive server identity, state: {self.state}")

        data = self.device._recv_mcu(0xFF02)
        if len(data) != 0x40:
            raise Exception("Wrong payload size")

        self.server_random = data[:0x20]
        logging.debug(f"server_random: {self.server_random.hex(' ')}")
        self.server_identity = data[0x20:]
        logging.debug(f"server_identity: {self.server_identity.hex(' ')}")

        session_key = _derive_session_key(
            self.psk, self.client_random + self.server_random, 0x44
        )

        self.symmetric_key = session_key[:0x10]
        logging.debug(f"symmetric_key: {self.symmetric_key.hex(' ')}")
        session_key = session_key[0x10:]

        self.symmetric_iv = session_key[:0x10]
        logging.debug(f"symmetric_iv: {self.symmetric_iv.hex(' ')}")
        session_key = session_key[0x10:]

        self.hmac_key = session_key[:0x20]
        logging.debug(f"hmac_key: {self.hmac_key.hex(' ')}")
        session_key = session_key[0x20:]

        self.hmac_client_counter_init = struct.unpack("<H", session_key[:2])[0]
        logging.debug(f"hmac_client_counter_init: {self.hmac_client_counter_init}")
        session_key = session_key[2:]

        self.hmac_server_counter_init = struct.unpack("<H", session_key[:2])[0]
        logging.debug(f"hmac_server_counter_init: {self.hmac_server_counter_init}")
        session_key = session_key[2:]

        assert not session_key

        self.client_identity = HMAC.HMAC(
            self.hmac_key, self.client_random + self.server_random, SHA256
        ).digest()
        logging.debug(f"client_identity: {self.client_identity.hex(' ')}")

        if self.server_identity != self.client_identity:
            raise Exception("Session key not derived correctly")

        self.device._send_mcu(0xFF03, self.client_identity + b"\xee" * 4)
        self.state = 4

    def _server_done_step(self) -> None:
        if self.state != 4:
            raise Exception(f"Cannot receive server done, state: {self.state}")

        data = self.device._recv_mcu(0xFF04)
        result = struct.unpack("<L", data)[0]
        if result != 0:
            raise Exception(f"Wrong handshake result reported: {result}")

        self.hmac_client_counter = self.hmac_client_counter_init
        self.hmac_server_counter = self.hmac_server_counter_init
        self.state = 5

    def establish_connection(self) -> None:
        logging.info("Starting GTLS handshake")
        self._client_hello_step()
        self._server_identity_step()
        self._server_done_step()
        logging.info("GTLS handshake successful")

    def is_connected(self):
        return self.state == 5

    def decrypt_sensor_data(self, encrypted_message):
        data_type = struct.unpack("<L", encrypted_message[:4])[0]
        if data_type != 0xAA01:
            raise Exception("Unexpected data type")

        msg_length = struct.unpack("<L", encrypted_message[4:8])[0]
        if msg_length != len(encrypted_message):
            raise Exception("Length mismatch")

        encrypted_payload = encrypted_message[8:-0x20]
        payload_hmac = encrypted_message[-0x20:]
        logging.debug(f"HMAC for encrypted payload: {payload_hmac.hex(' ')}")

        gea_encrypted_data = b""
        for block_idx in range(15):
            if block_idx % 2 == 0:
                if block_idx == 0:
                    gea_encrypted_data += encrypted_payload[:0x3A7]
                    encrypted_payload = encrypted_payload[0x3A7:]
                elif block_idx == 14:
                    assert len(gea_encrypted_data) == 0x3A7 + 0x3F0 * 13
                    gea_encrypted_data += encrypted_payload
                else:
                    gea_encrypted_data += encrypted_payload[:0x3F0]
                    encrypted_payload = encrypted_payload[0x3F0:]
            else:
                cipher = AES.new(self.symmetric_key, AES.MODE_CBC, iv=self.symmetric_iv)
                gea_encrypted_data += cipher.decrypt(encrypted_payload[:0x3F0])
                encrypted_payload = encrypted_payload[0x3F0:]

        hmac_data = struct.pack("<L", self.hmac_server_counter)
        hmac_data += gea_encrypted_data[-0x400:]
        computed_hmac = HMAC.HMAC(self.hmac_key, hmac_data, SHA256).digest()

        if computed_hmac != payload_hmac:
            raise Exception("HMAC verification failed")
        logging.debug("Encrypted payload HMAC verified")

        self.hmac_server_counter = (self.hmac_server_counter + 1) & 0xFFFFFFFF
        logging.debug(f"HMAC server counter is now: {self.hmac_server_counter}")

        if len(gea_encrypted_data) < 5:
            raise Exception("Encrypted payload too short")
        # The first five bytes are always discarded (alignment?)
        gea_encrypted_data = gea_encrypted_data[5:]

        msg_gea_crc = decode_u32(gea_encrypted_data[-4:])
        gea_encrypted_data = gea_encrypted_data[:-4]
        logging.debug(f"GEA data CRC: {hex(msg_gea_crc)}")

        computed_gea_crc = Crc32Mpeg2.calc(gea_encrypted_data)
        if computed_gea_crc != msg_gea_crc:
            raise Exception("CRC check failed")
        logging.debug("GEA data CRC verified")

        gea_key = self.symmetric_key[:4]
        logging.debug(f"GEA key: {gea_key.hex(' ')}")

        return _gea_decrypt(gea_key, gea_encrypted_data)


def _derive_session_key(psk, random_data: bytes, session_key_length: int) -> bytes:
    seed = b"master secret" + random_data

    session_key = b""
    A = seed
    while len(session_key) < session_key_length:
        A = HMAC.HMAC(psk, A, SHA256).digest()
        session_key += HMAC.HMAC(psk, A + seed, SHA256).digest()

    return session_key[:session_key_length]


def decode_u32(data: bytes):
    assert len(data) == 4
    return data[0] * 0x100 + data[1] + data[2] * 0x1000000 + data[3] * 0x10000


def _gea_decrypt(key, encrypted_data) -> bytes:
    key = struct.unpack("<L", key)[0]

    decrypted_data = b""
    for data_idx in range(0, len(encrypted_data), 2):
        uVar3 = (key >> 1 ^ key) & 0xFFFFFFFF
        uVar2 = (
            (
                (
                    (
                        (
                            (
                                (
                                    (key >> 0xF & 0x2000 | key & 0x1000000) >> 1
                                    | key & 0x20000
                                )
                                >> 2
                                | key & 0x1000
                            )
                            >> 3
                            | (key >> 7 ^ key) & 0x80000
                        )
                        >> 1
                        | (key >> 0xF ^ key) & 0x4000
                    )
                    >> 2
                    | key & 0x2000
                )
                >> 2
                | uVar3 & 0x40
                | key & 0x20
            )
            >> 1
            | (key >> 9 ^ key << 8) & 0x800
            | (key >> 0x14 ^ key * 2) & 4
            | (key * 8 ^ key >> 0x10) & 0x4000
            | (key >> 2 ^ key >> 0x10) & 0x80
            | (key << 6 ^ key >> 7) & 0x100
            | (key & 0x100) << 7
        )
        uVar2 = uVar2 & 0xFFFFFFFF
        uVar1 = key & 0xFFFF
        key = ((key ^ (uVar3 >> 0x14 ^ key) >> 10) << 0x1F | key >> 1) & 0xFFFFFFFF

        input_element = struct.unpack("<H", encrypted_data[data_idx : data_idx + 2])[0]
        stream_val = ((uVar2 >> 8) & 0xFFFF) + (uVar2 & 0xFF | uVar1 & 1) * 0x100
        decrypted_data += struct.pack("<H", input_element ^ stream_val)

    assert len(encrypted_data) == len(decrypted_data)
    return decrypted_data
