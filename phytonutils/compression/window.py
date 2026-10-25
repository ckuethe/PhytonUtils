from .constants import (
    WINDOW_SIZE,
    WINDOW_INITIAL_INDEX,
    WINDOW_FILL_VALUE,
    MAX_CODED,
    MAX_UNCODED,
)


class Window:
    def __init__(self):
        self._t = bytearray(WINDOW_SIZE)
        for i in range(WINDOW_INITIAL_INDEX):
            self._t[i] = WINDOW_FILL_VALUE

    def index(self, i):
        return i & (WINDOW_SIZE - 1)

    def find(self, window_index, buf, exhaustive):
        first_data = buf[0]

        offset_index = -1
        length = -1

        for i in range(WINDOW_SIZE):
            current_offset_index = self.index(window_index + i - 1)
            if self._t[current_offset_index] == first_data:
                t2 = bytearray(self._t)
                lookup_index2 = t2_index = self.index(window_index + 1)

                # emulate t2.SetByte(window_index, firstData)
                t2[self.index(window_index)] = first_data

                match_size = 1

                for j in range(1, len(buf)):
                    if j >= (MAX_CODED - 1):
                        break
                    # emulate t2.GetSetByte(current_offset_index + j, lookup_index2)
                    data = t2[self.index(current_offset_index + j)]
                    t2[self.index(lookup_index2)] = data
                    lookup_index2 = self.index(lookup_index2 + 1)
                    if data != buf[j]:
                        break
                    match_size += 1

                if match_size > length and match_size >= MAX_UNCODED:
                    offset_index = current_offset_index
                    length = match_size
                    if not exhaustive:
                        return offset_index, length

        return offset_index, length

    def peek(self, offset_index, length, buf):
        for j in range(length):
            buf[j] = self._t[self.index(offset_index + j)]
        return buf[:length]

    def getset(self, offset_index, window_index, length, buf):
        for j in range(length):
            data = self._t[self.index(offset_index + j)]
            self._t[self.index(window_index + j)] = data
            buf[j] = data
        return self.index(window_index + length), buf[:length]

    def set(self, window_index, buf):
        for j in range(len(buf)):
            self._t[self.index(window_index + j)] = buf[j]
        return self.index(window_index + len(buf))

    def getset_byte(self, offset_index, window_index):
        data = self._t[self.index(offset_index)]
        self._t[self.index(window_index)] = data
        return self.index(window_index + 1), data

    def get_byte(self, offset_index):
        return self._t[self.index(offset_index)]

    def set_byte(self, window_index, data):
        self._t[self.index(window_index)] = data
        return self.index(window_index + 1)
