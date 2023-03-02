#!/usr/bin/env python3

import tool
import argparse
import os

def get_inverse_coverage(image):
    notcovered = 0
    for pixel in image:
        if pixel > 4000:
            notcovered = notcovered + 1

    return notcovered

def get_histogram(image):
    res = [0] * 256
    for pixel in image:
        idx = int(pixel / 16)
        res[idx] = res[idx] + 1

    return res

def get_cumul_histogram(hist):
    res = [0] * 256
    res[0] = hist[0]
    for idx in range(1, len(hist)):
        res[idx] = hist[idx] + res[idx - 1]

    return res

def get_level(cumul_hist, value):
    for idx in range(len(cumul_hist)):
        if cumul_hist[idx] > value:
            return idx

    return len(cumul_hist)

def remove_border(image, width, height):
    for idx in range(width):
        image[idx] = 0
        image[(height - 1) * width + idx] = 0
    for idx in range(height):
        image[idx * width] = 0
        image[idx * width + width - 1] = 0

def main(args):
    (bg_width, bg_height, bg_depth, bg_img) = tool.read_pgm(args.background)
    (width, height, depth, raw_img) = tool.read_pgm(args.image)

    assert bg_width == width and bg_height == height
    assert bg_depth == depth == 4095

    remove_border(raw_img, width, height)
    remove_border(bg_img, width, height)

    subtracted = []
    total = width * height - width * 2 - height * 2 + 4
    coverage = total - get_inverse_coverage(raw_img)
    print(f"Coverage: {coverage} out of {total}, %d%%" % (100 * coverage / total))
    for bg_pixel, raw_pixel in zip(bg_img, raw_img):
        val = abs(1000 + raw_pixel - bg_pixel)
        if val < 0:
            val = 0
        if val > 4095:
            val = 4095
        subtracted.append(val)

    # Black and white levels depend on the scanner model
    cumul_hist = get_cumul_histogram(get_histogram(subtracted))
    black_lvl = get_level(cumul_hist, 100) * 16
    if black_lvl > 1000:
        black_lvl = 1000
    print(f"Black level: {black_lvl}")
    #black_lvl = 700
    white_lvl = 1500

    # map [black_lvl .. white_lvl] to [0 .. 4095]
    # pixel < black_lvl: pixel = 0
    # pixel > white_lvl: pixel = 4095
    # 4096 * (pixel - black_lvl) / (white_lvl - black_lvl)

    res = []
    for pixel in subtracted:
        if pixel < black_lvl:
            pixel = 0
        elif pixel > white_lvl:
            pixel = 4095
        else:
            pixel = int(4096 * (pixel - black_lvl) / (white_lvl - black_lvl))
        res.append(pixel)

    tool.write_pgm(res, height, width, "result.pgm")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("background", type=str)
    parser.add_argument("image", type=str)
    args = parser.parse_args()

    main(args)
