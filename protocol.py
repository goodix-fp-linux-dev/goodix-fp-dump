from abc import ABC, abstractmethod
from time import sleep, time
from typing import Optional

from usb.control import get_status
from usb.core import Device as USBDevice
from usb.core import USBError, find
from usb.legacy import (CLASS_DATA, CLASS_VENDOR_SPEC, ENDPOINT_IN,
                        ENDPOINT_OUT, ENDPOINT_TYPE_BULK)
from usb.util import endpoint_direction, endpoint_type, find_descriptor


class Protocol(ABC):

    @abstractmethod
    def __init__(self,
                 vendor: int,
                 product: int,
                 timeout: Optional[float] = 5) -> None:
        ...

    @abstractmethod
    def write(self, data: bytes, timeout: Optional[float] = 5) -> None:
        ...

    @abstractmethod
    def read(self, size: int = 0x4000, timeout: Optional[float] = 5) -> bytes:
        ...

    @abstractmethod
    def disconnect(self, timeout: Optional[float] = 5) -> None:
        ...


class USBProtocol(Protocol):

    def __init__(self,
                 vendor: int,
                 product: int,
                 timeout: Optional[float] = 5) -> None:
        super().__init__(vendor, product, timeout)

        if timeout is not None:
            timeout += time()

        while True:
            device = find(idVendor=vendor, idProduct=product)

            if device is not None:
                try:
                    get_status(device)
                    break

                except USBError as error:
                    if (error.backend_error_code != -1 and
                            error.backend_error_code != -4):
                        raise error

            if timeout is not None and time() > timeout:
                if device is None:
                    raise TimeoutError("Device not found", -5, 19)

                raise TimeoutError("Invalid device state", -12, 131)

            sleep(0.01)

        self.device: USBDevice = device

        print(f"Found Goodix device: \"{self.device.product}\" "
              f"from \"{self.device.manufacturer}\" "
              f"on bus {self.device.bus} "
              f"address {self.device.address}.")

        interface_data = find_descriptor(
            self.device.get_active_configuration(),
            custom_match=lambda interface: interface.bInterfaceClass ==
            CLASS_DATA or interface.bInterfaceClass == CLASS_VENDOR_SPEC)

        if interface_data is None:
            raise ConnectionError("Interface data not found", -5, 6)

        print(f"Found interface data: {interface_data.bInterfaceNumber}")

        if self.device.is_kernel_driver_active(interface_data.bInterfaceNumber):
            self.device.detach_kernel_driver(interface_data.bInterfaceNumber)

        endpoint_in = find_descriptor(
            interface_data,
            custom_match=lambda endpoint: endpoint_direction(
                endpoint.bEndpointAddress) == ENDPOINT_IN and endpoint_type(
                    endpoint.bmAttributes) == ENDPOINT_TYPE_BULK)

        if endpoint_in is None:
            raise ConnectionError("Endpoint in not found", -5, 6)

        self.endpoint_in: int = endpoint_in.bEndpointAddress
        print(f"Found endpoint in: {hex(self.endpoint_in)}")

        endpoint_out = find_descriptor(
            interface_data,
            custom_match=lambda endpoint: endpoint_direction(
                endpoint.bEndpointAddress) == ENDPOINT_OUT and endpoint_type(
                    endpoint.bmAttributes) == ENDPOINT_TYPE_BULK)

        if endpoint_out is None:
            raise ConnectionError("Endpoint out not found", -5, 6)

        self.endpoint_out: int = endpoint_out.bEndpointAddress
        print(f"Found endpoint out: {hex(self.endpoint_out)}")

        self.device.set_configuration()

    def write(self, data: bytes, timeout: Optional[float] = 5) -> None:
        timeout = 0 if timeout is None else round(timeout * 1000)

        length = len(data)
        if length % 0x40:
            data += b"\x00" * (0x40 - length % 0x40)

        for i in range(0, length, 0x40):
            self.device.write(self.endpoint_out, data[i:i + 0x40], timeout)

    def read(self, size: int = 0x4000, timeout: Optional[float] = 5) -> bytes:
        timeout = 0 if timeout is None else round(timeout * 1000)

        return self.device.read(self.endpoint_in, size, timeout).tobytes()

    def disconnect(self, timeout: Optional[float] = 5) -> None:

        if timeout is not None:
            timeout += time()

        while True:
            try:
                get_status(self.device)

            except USBError as error:
                if (error.backend_error_code == -1 or
                        error.backend_error_code == -4):
                    break

                raise error

            if timeout is not None and time() > timeout:
                raise TimeoutError("Device is still connected", -7, 110)

            sleep(0.01)
