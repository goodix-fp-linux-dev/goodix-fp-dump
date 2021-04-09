It is possible to enable verbose logging in the Windows driver by setting some
registry keys.

See the `goodix_enable_logs.reg` file for an example.

After merging the registry file from above and rebooting, new log files will be
created in the hidden directory `C:\ProgramData\Goodix`:

* ENGINE.log
* WBDI.log (an example is provided)
