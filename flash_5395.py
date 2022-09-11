import flasher_53x5

# A 5395 sensor in IAP mode reports 5740 as USB PID
flasher_53x5.main(0x5740, "GF5288_HTSEC_APP_10020.bin")
