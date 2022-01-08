# Goodix FP Dump

All our work to make Goodix fingerprint sensors work on Linux.
You can communicate with us at the Discord channel [Goodix Linux Development](https://discord.com/invite/6xZ6k34Vqg)

The libfprint driver development can be found at https://github.com/rootd/libfprint

## How to use it

```
$ python --version # Must be Python 3.8 or newer
$ sudo pip3 install pyusb crcmod
$ git clone --recurse-submodules https://github.com/mpi3d/goodix-fp-dump.git
$ cd goodix-fp-dump
$ sudo lsusb -vd "27c6:" | grep "idProduct" # Returns the device ID
$ sudo python3 run_5110.py # Change "5110" to your device ID
```
