#!/usr/bin/env python3

import tool
import argparse

def crop(image, width, height, x, y, new_width, new_height):
    res = []
    for y1 in range(y, y + new_height):
        idx = y1 * width + x
        res = res + image[idx:idx + new_width]

    return res

def threshold_filter(image, low, high):
    result = []
    coverage = 0
    for pixel in image:
        if pixel < low:
            result.append(0)
        elif pixel > high:
            result.append(4095)
        else:
            coverage = coverage + 1
            result.append(pixel)

    return result, coverage

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

def mean_filter(image, width, height, mask_radius, mask = None):
    res = []
    for y in range(0, height):
        for x in range(0, width):
            cnt = 0
            val = 0
            for y2 in range(y - mask_radius, y + mask_radius + 1):
                if y2 < 0 or y2 >= height:
                    continue
                for x2 in range(x - mask_radius, x + mask_radius + 1):
                    if x2 < 0 or x2 >= width:
                        continue
                    if mask:
                        weight = mask[(x2 - x - mask_radius) + (mask_radius * 2 + 1) * (y2 - y - mask_radius)]
                    else:
                        weight = 1
                    cnt = cnt + weight
                    val = val + image[y2 * width + x2] * weight
            if cnt == 0:
                cnt = 1
            val = val / cnt
            res.append(val)

    return res

def subtract_image(bg_img, img, offset, bg_weight, img_weight):
    subtracted = []
    for bg_pixel, img_pixel in zip(bg_img, img):
        val = offset + img_weight * img_pixel / 100 - bg_weight * bg_pixel / 100
        if val < 0:
            val = 0
        if val > 4095:
            val = 4095
        subtracted.append(val)
    return subtracted

def hist_equalization(image, black_lvl, white_lvl):
    # map [black_lvl .. white_lvl] to [0 .. 4095]
    # pixel < black_lvl: pixel = 0
    # pixel > white_lvl: pixel = 4095
    # 4096 * (pixel - black_lvl) / (white_lvl - black_lvl)
    res = []
    for pixel in image:
        if pixel < black_lvl:
            pixel = 0
        elif pixel > white_lvl:
            pixel = 4095
        else:
            pixel = int(4095 * (pixel - black_lvl) / (white_lvl - black_lvl))
        res.append(pixel)

    return res

def main(args):
    (bg_width, bg_height, bg_depth, bg_img) = tool.read_pgm(args.background)
    (width, height, depth, raw_img) = tool.read_pgm(args.image)

    assert bg_width == width and bg_height == height
    assert bg_depth == depth == 4095

    # Crop image to drop black border
    raw_img = crop(raw_img, width, height, 1, 1, width - 2, height - 2)
    bg_img = crop(bg_img, width, height, 1, 1, width - 2, height - 2)
    width = width - 2
    height = height - 2

    hist = get_histogram(raw_img)
    print("Raw image histogram: %s" % hist)

    subtracted = subtract_image(bg_img, raw_img, 1000, 100, 100)
    subtracted, coverage = threshold_filter(subtracted, 0, 1700)
    total = width * height
    print(f"Coverage: {coverage} out of {total}, %d%%" % (100 * coverage / total))

    hist = get_histogram(subtracted)
    print("Subtracted image histogram: %s" % hist)
    total = width * height - hist[0] - hist[1] - hist[2] - hist[255] - hist[254] - hist[253]
    # We don't want to account black and white pixels
    hist[0] = 0
    hist[255] = 0
    cumul_hist = get_cumul_histogram(hist)

    # Black level starts at 0.1% of total pixels
    black_lvl = get_level(cumul_hist, 1 * total / 1000) * 16
    print(f"Black level: {black_lvl}")

    # White level starts at 99% of total pixels
    white_lvl = get_level(cumul_hist, 99 * total / 100) * 16
    print(f"Estimated white level: {white_lvl}")

    res = hist_equalization(subtracted, black_lvl, white_lvl)

    hist = get_histogram(res)
    print("Histogram equalized image histogram: %s" % hist)

    mean_1 = mean_filter(res, width, height, 1, [1, 2, 1, 2, 4, 2, 1, 2, 1])
    mean_sub_1 = subtract_image(mean_1, res, 0, 100, 200)

    tool.write_pgm(res, height, width, "stage-2-hist-eq.pgm")
    tool.write_pgm(subtracted, height, width, "stage-1-subtracted.pgm")
    tool.write_pgm(mean_1, height, width, "stage-3-mean.pgm")
    tool.write_pgm(mean_sub_1, height, width, "result.pgm")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("background", type=str)
    parser.add_argument("image", type=str)
    args = parser.parse_args()

    main(args)
