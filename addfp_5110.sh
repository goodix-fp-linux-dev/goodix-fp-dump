#!/bin/bash
python run_5110.py
mogrify -crop 64x80+0+0 -format jpg ./fingerprint.pgm
mkdir -p fpr
mv ./fingerprint.jpg fpr/$(cat ./id).jpg
echo $(($(cat ./id) + 1)) > ./id

