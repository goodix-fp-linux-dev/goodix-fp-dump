from PIL import Image, ImageDraw

data = open("data.txt")

import numpy as np


def read_uint12(data_chunk):
    data = np.frombuffer(data_chunk, dtype=np.uint8)
    fst_uint8, mid_uint8, lst_uint8 = np.reshape(
        data, (data.shape[0] // 3, 3)).astype(np.uint16).T
    fst_uint12 = (fst_uint8 << 4) + (mid_uint8 >> 4)
    snd_uint12 = ((mid_uint8 % 16) << 8) + lst_uint8
    return np.reshape(
        np.concatenate((fst_uint12[:, None], snd_uint12[:, None]), axis=1),
        2 * fst_uint12.shape[0])


# t = None

# for i in range(1, 103):

#     img = Image.new("RGB", (i, i))
#     draw = ImageDraw.Draw(img)

#     data.seek(0)

#     for y in range(i):
#         for x in range(i):
#             if t is None:
#                 t = read_uint12(bytearray.fromhex(data.read(6)))
#                 draw.point((x, y), (0, int(t[0] * 255 / 4096), 0))
#             else:
#                 draw.point((x, y), (0, int(t[1] * 255 / 4096), 0))
#                 t = None

#     img.save("fingers/finger{0}x{0}.png".format(i))

# data.close()

for i in range(1, 103):

    img = Image.new("RGB", (i, i))
    draw = ImageDraw.Draw(img)

    data.seek(0)

    for y in range(i):
        for x in range(i):
            t = read_uint12(bytearray.fromhex(data.read(6)))
            draw.point((x, y),
                       (int(t[1] * 255 / 4096), int(t[0] * 255 / 4096), 0))
    img.save("fingers/finger{0}x{0}.png".format(i))

data.close()
