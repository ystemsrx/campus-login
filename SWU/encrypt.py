# -*- coding: utf-8 -*-

def _str_to_bt_js(str_block):
    bt = [0] * 64
    leng = len(str_block)
    if leng < 4:
        for i in range(leng):
            k = ord(str_block[i])
            for j in range(16):
                # 2^(15-j)
                pow2 = 1 << (15 - j)
                bt[16 * i + j] = (k // pow2) % 2
    else:
        for i in range(4):
            k = ord(str_block[i])
            for j in range(16):
                pow2 = 1 << (15 - j)
                bt[16 * i + j] = (k // pow2) % 2
    return bt


def _get_key_bytes_js(key):
    key_bytes = []
    leng = len(key)
    iterator = leng // 4
    remainder = leng % 4
    for i in range(iterator):
        key_bytes.append(_str_to_bt_js(key[i * 4:(i + 1) * 4]))
    if remainder > 0:
        key_bytes.append(_str_to_bt_js(key[iterator * 4:]))
    return key_bytes


def _init_permute_js(originalData):
    ipByte = [0] * 64
    m, n = 1, 0
    for i in range(4):
        j, k = 7, 0
        while j >= 0:
            ipByte[i * 8 + k] = originalData[j * 8 + m]
            ipByte[i * 8 + k + 32] = originalData[j * 8 + n]
            j -= 1
            k += 1
        m += 2
        n += 2
    return ipByte


def _expand_permute_js(rightData):
    epByte = [0] * 48
    for i in range(8):
        epByte[i * 6 + 0] = rightData[31] if i == 0 else rightData[i * 4 - 1]
        epByte[i * 6 + 1] = rightData[i * 4 + 0]
        epByte[i * 6 + 2] = rightData[i * 4 + 1]
        epByte[i * 6 + 3] = rightData[i * 4 + 2]
        epByte[i * 6 + 4] = rightData[i * 4 + 3]
        epByte[i * 6 + 5] = rightData[0] if i == 7 else rightData[i * 4 + 4]
    return epByte


# S-Box
_SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

_P_IDX = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
          1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

_FP_IDX = [
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24
]


def _get_box_binary(val):
    return [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]


def _sbox_permute_js(expandByte):
    out32 = [0] * 32
    for m in range(8):
        i = expandByte[m * 6 + 0] * 2 + expandByte[m * 6 + 5]
        j = (expandByte[m * 6 + 1] << 3) | (expandByte[m * 6 + 2] << 2) | (expandByte[m * 6 + 3] << 1) | expandByte[m * 6 + 4]
        binary = _get_box_binary(_SBOXES[m][i][j])
        out32[m * 4 + 0] = binary[0]
        out32[m * 4 + 1] = binary[1]
        out32[m * 4 + 2] = binary[2]
        out32[m * 4 + 3] = binary[3]
    return out32


def _p_permute_js(sBoxByte):
    return [sBoxByte[i] for i in _P_IDX]


def _xor_js(a, b):
    return [x ^ y for x, y in zip(a, b)]


def _finally_permute_js(endByte):
    return [_ for _ in (endByte[i] for i in _FP_IDX)]


def _generate_keys_js(keyByte):
    key = [0] * 56
    keys = [[0] * 48 for _ in range(16)]
    loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    # PC-1
    for i in range(7):
        k = 7
        for j in range(8):
            key[i * 8 + j] = keyByte[8 * k + i]
            k -= 1
    # 16 轮循环左移 + PC-2
    for i in range(16):
        for _ in range(loop[i]):
            tempLeft = key[0]
            tempRight = key[28]
            for k in range(27):
                key[k] = key[k + 1]
                key[28 + k] = key[29 + k]
            key[27] = tempLeft
            key[55] = tempRight
        tempKey = [0] * 48
        idx = [
            13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
            40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
        ]
        for m in range(48):
            tempKey[m] = key[idx[m]]
        keys[i] = tempKey
    return keys


def _enc_block_js(dataByte, keyByte):
    keys = _generate_keys_js(keyByte)
    ip = _init_permute_js(dataByte)
    L, R = ip[:32], ip[32:]
    for i in range(16):
        L, R = R, _xor_js(_p_permute_js(_sbox_permute_js(_xor_js(_expand_permute_js(R), keys[i]))), L)
    return _finally_permute_js(R + L)


def _dec_block_js(dataByte, keyByte):
    keys = _generate_keys_js(keyByte)
    ip = _init_permute_js(dataByte)
    L, R = ip[:32], ip[32:]
    for i in range(16):
        L, R = R, _xor_js(_p_permute_js(_sbox_permute_js(_xor_js(_expand_permute_js(R), keys[15 - i]))), L)
    return _finally_permute_js(R + L)


def _bt64_to_hex_js(byteData):
    HEX = "0123456789ABCDEF"
    out = []
    for i in range(16):
        v = (byteData[i * 4 + 0] << 3) | (byteData[i * 4 + 1] << 2) | (byteData[i * 4 + 2] << 1) | byteData[i * 4 + 3]
        out.append(HEX[v])
    return "".join(out)


def _hex_to_bt64_js(hexs):
    M = {c: i for i, c in enumerate("0123456789ABCDEF")}
    binary = []
    for i in range(16):
        v = M[hexs[i].upper()]
        binary.extend([(v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1])
    return binary


def strEnc_js(data, firstKey, secondKey="", thirdKey=""):
    encData = ""
    firstKeyBt = _get_key_bytes_js(firstKey) if firstKey else []
    secondKeyBt = _get_key_bytes_js(secondKey) if secondKey else []
    thirdKeyBt = _get_key_bytes_js(thirdKey) if thirdKey else []
    for i in range(0, len(data), 4):
        bt = _str_to_bt_js(data[i:i + 4])
        tmp = bt[:]
        for kb in firstKeyBt:
            tmp = _enc_block_js(tmp, kb)
        for kb in secondKeyBt:
            tmp = _enc_block_js(tmp, kb)
        for kb in thirdKeyBt:
            tmp = _enc_block_js(tmp, kb)
        encData += _bt64_to_hex_js(tmp)
    return encData


def strDec_js(hex_data, firstKey, secondKey="", thirdKey=""):
    out = []
    firstKeyBt = _get_key_bytes_js(firstKey) if firstKey else []
    secondKeyBt = _get_key_bytes_js(secondKey) if secondKey else []
    thirdKeyBt = _get_key_bytes_js(thirdKey) if thirdKey else []
    for i in range(0, len(hex_data), 16):
        bt = _hex_to_bt64_js(hex_data[i:i + 16])
        tmp = bt[:]
        for kb in reversed(thirdKeyBt):
            tmp = _dec_block_js(tmp, kb)
        for kb in reversed(secondKeyBt):
            tmp = _dec_block_js(tmp, kb)
        for kb in reversed(firstKeyBt):
            tmp = _dec_block_js(tmp, kb)
        for off in range(0, 64, 16):
            code = 0
            for j in range(16):
                code = (code << 1) | tmp[off + j]
            if code != 0:
                out.append(chr(code))
    return "".join(out)
