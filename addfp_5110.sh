#!/bin/bash
python /home/mango/goodix-fp-dump/run_5110.py
mogrify -crop 64x80+0+0 -format jpg ./fingerprint.pgm
mv ./fingerprint.jpg /home/mango/fpr/$(cat ./id).jpg
echo $(($(cat ./id) + 1)) > ./id

