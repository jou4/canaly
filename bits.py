def split_bits(bs: bytes, ss: list[int], end: int = -1):
    """Split bytes into list of bits as specified positions
    Args:
    bs  array of byte
    ss  array of starting position to split
    end position to stop process
    """
    # index of current starting postion
    s_index = 0

    # clarify total range and first range to process
    pos = ss[s_index]
    end_pos = len(bs) << 3 if end < 0 else end
    next_pos = min(end_pos, ss[s_index + 1]) if (s_index + 1) < len(ss) else end_pos

    # index of current byte
    b_index = pos >> 3

    # result of the function
    bits_list = []
    # extracted bits
    bits = 0

    while(pos < end_pos):
        # remaining length to extract
        rem_len = next_pos - pos

        while(pos < next_pos):
            # load byte to process
            b = bs[b_index]

            # clarify range to process in the byte
            max_pos = (b_index + 1) << 3
            to_pos = min(pos + rem_len, max_pos)
            length = to_pos - pos

            # remove unnecessary bits from left side
            b = b & (0xFF >> (pos % 8))
            # remove unnecessary bits from right side
            b = b >> (max_pos - to_pos)

            # store
            bits = (bits << length) + b

            # update remaining length and move cursor
            rem_len -= length
            pos += length

            # continue to next byte
            if pos >= max_pos:
                b_index += 1

        # push to result
        bits_list.append(bits)

        # clear bits
        bits = 0

        # move onto next range
        s_index += 1
        next_pos = min(end_pos, ss[s_index + 1]) if (s_index + 1) < len(ss) else end_pos

    return bits_list


def extract_bits(bs: bytes, s: int, l: int):
    """Extract bits in specified ranges from bytes
    Args:
    bs  array of byte
    s   starting index to extract
    l   length to extract
    """
    bits_list = split_bits(bs, [s], s + l)

    return bits_list[0] if len(bits_list) > 0 else None


def hexstr_to_bytes(hex_string):
    """Convert hex string to byte array
    Args:
    hex_string  hex string
    """
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string

    int_array = []

    for i in range(0, len(hex_string), 2):
        int_array.append(int(hex_string[i:i+2], 16))

    return bytes(int_array)

