def generate_sequence(a):
    sequence = []
    pos = 0
    count_prev = 0
    count_curr = 1
    for value in a:
        xor_value = value ^ count_curr
        sequence.append(xor_value)
        count_curr += count_prev
        count_prev = count_curr-count_prev
        print(f"pos {pos} xor = {hex(count_curr)}")
        pos += 1
    return sequence


def sequence_to_ascii(sequence):
    ascii_list = []
    for value in sequence:
        ascii_value = value % 128
        ascii_char = chr(ascii_value)
        ascii_list.append(ascii_char)
    return ascii_list

a = [0x75, 0x6B, 0x61, 0x77, 0x63, 0x73, 0x7A, 0x61, 0x0F, 0x43, 0x31, 0xF5, 0xC4, 0x10D, 0x215, 0x3B4, 0x652, 0xA77, 0x103A, 0x1A02, 0x2AA3, 0x455C, 0x6FC5, 0xB518, 0x12534, 0x1DA71, 0x2FF26, 0x4D915, 0x7D8C6, 0xCB25]

sequence = generate_sequence(a)
flag = str("".join(sequence_to_ascii(sequence)))
print(flag)
#tjctf{wt-the-twoooooas48%@dfs}

