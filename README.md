# Goodix FP Dump

All our work to make Goodix fingerprint sensors work on Linux.
You can communicate with us at the Discord channel [Goodix Fingerprint Linux Development](https://discord.com/invite/6xZ6k34Vqg).

The libfprint driver development can be found at https://github.com/rootd/libfprint.

## How to use it

We do not recommend using this for now. This is very unstable.
Also, this make people to create many duplicates issues to tell us that it doesn't work. Of course, we already know that.
Because of this, programs execution might be disabled in the future.
So please think carefully before running this or creating an issue.

```
$ python --version # Must be Python 3.10 or newer
$ sudo pip install pyusb crcmod
$ git clone --recurse-submodules https://github.com/mpi3d/goodix-fp-dump.git
$ cd goodix-fp-dump
$ sudo lsusb -vd "27c6:" | grep "idProduct" # Returns the device ID
$ sudo python3 run_5110.py # Change "5110" to your device ID
```
