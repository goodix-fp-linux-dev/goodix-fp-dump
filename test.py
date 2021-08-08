import usb.control
import usb.core
import usb.util

from goodix import Device

VID = 0x27c6
PID = 0x538d

dev: usb.core.Device = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None:
    print('not found')

print(f'Total configs: {len(dev.configurations())}')

print('\tcfg\tintf\tendp')
for ci, cfg in enumerate(dev.configurations()):
    print(f'\t{ci+1}/{dev.bNumConfigurations}: ')
    for ii, intf in enumerate(cfg.interfaces()):
        print(f'\t\t{ii+1}/{cfg.bNumInterfaces}: {intf.bInterfaceClass}')
        for epi, ep in enumerate(intf.endpoints()):
            print(
                f'\t\t\t{epi+1}/{intf.bNumEndpoints}: {ep.bEndpointAddress} | {usb.util.endpoint_direction(ep.bEndpointAddress)}'
            )

cfg = dev.get_active_configuration()

d = Device(0x538d)

d.nop()
d.enable_chip(True)
d.nop()

firmware = d.firmware_version()
print(f'fw: {firmware}')
psk = d.preset_psk_read_r(0xbb020003, 0)
print(f'psk: {psk}')
