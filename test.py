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


print(read_uint12(bytearray.fromhex('000000')))
