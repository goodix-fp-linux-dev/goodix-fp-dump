#include <stdio.h>
#include <libusb-1.0/libusb.h>

int init()
{
}

main()
{
    const uint16_t vendor_id = 0x27c6, product_id = 0x5110;
    unsigned char *data = "\x00\x00";
    int ret;

    // Init
    if (ret = libusb_init(NULL) != LIBUSB_SUCCESS)
    {
        fprintf(stderr, "Failed to init libusb: %s\n", libusb_error_name(ret));
        return ret;
    }
    if (ret = libusb_set_option(
                  NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_DEBUG) != LIBUSB_SUCCESS)
    {
        fprintf(stderr, "Failed to configure libusb: %s\n", libusb_error_name(ret));
    }

    // Open device
    libusb_device_handle *dev_handle = libusb_open_device_with_vid_pid(
        NULL, vendor_id, product_id);
    if (dev_handle == NULL)
    {
        fprintf(stderr, "Device not found\n");
        ret = 1;
        goto exit;
    }

    //Claim interface
    if (ret = libusb_set_auto_detach_kernel_driver(dev_handle, 1) != LIBUSB_SUCCESS)
    {
        fprintf(stderr, "Failed to set auto detach: %s\n",
                libusb_error_name(ret));
        goto close;
    }
    if (ret = libusb_claim_interface(dev_handle, 0) != LIBUSB_SUCCESS)
    {
        fprintf(stderr, "Failed to claim interface: %s\n",
                libusb_error_name(ret));
        goto close;
    }

    ret = libusb_control_transfer(
        dev_handle, 0x80, LIBUSB_REQUEST_GET_STATUS, 0x0000, 0x0000, data, 0, 10000);
    if (ret < LIBUSB_SUCCESS)
    {
        fprintf(stderr, "Failed to control transfer: %s\n",
                libusb_error_name(ret));
        goto release;
    }
    else if (ret != 0)
    {
        fprintf(stderr, "Failed to control transfer %d/0\n",
                ret);
        goto release;
    }

release:
    if (ret = libusb_release_interface(dev_handle, 0) != LIBUSB_SUCCESS)
    {
        fprintf(stderr, "Failed to release interface %s\n",
                libusb_error_name(ret));
        goto close;
    }
close:
    libusb_close(dev_handle);
exit:
    libusb_exit(NULL);
    return ret;
}
