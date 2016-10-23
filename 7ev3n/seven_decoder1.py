#!/usr/bin/python2.7
# CC-BY: hasherezade
"""Decoder for 7even-HONE$T ransomware - variant A"""

import argparse
import os

PREFIX = 'M'
SUFFIX = '*'

#for 7ev3n HONE$T:
FNAME_KEY_R4A = 'ANOASudgfjfirtj4k504iojm5io5nm59uh5vob5mho5p6gf2u43i5hojg4mf4i05j6g594cn9mjg6h'
FNAME_KEY_R5A = 'ASIBVbhciJ5hv6bjyuwetjykok7mbvtbvtiJ5h6jg54ifj0655iJ5hok7mbok7mbvtvtv6bjfib56j45fkmbvtiJ5hv6bokok7mbvt7mbvtj55nf4y8uhmvbi7knd4ium6iok7mbvtiiJ5hv6bjJ5hhigmubn56gfiok7mbvtjnmvu9bvtiJ5h6biok7mbvt7mbgi5fmuv65mg9fi4dm5v6iognfun5u6inguifbv5ibomlimmhnbjvfchbgnhugk5ybvtc3cty5'

def decode(data, key, offset=0):
    maxlen = len(data)
    keylen = len(key)
    j = 0 #key index
    decoded = bytearray()
    for i in range(offset, maxlen):
        dec = data[i] ^ key[j % keylen]
        j += 1
        decoded.append(dec) 
    return decoded

def search_suffix(filep):
    filep.seek(0, os.SEEK_END)
    size = filep.tell()

    pos = size - 1
    filep.seek(pos, os.SEEK_SET)
    data = filep.read(1)
    if data != '\x0a':
        return None
    pos -= 1
    buffer = ""
    prev_data = None
    while pos > 0:
        filep.seek(pos, os.SEEK_SET)
        data = filep.read(1)
        pos -= 1
        if data == SUFFIX and prev_data == SUFFIX:
            break
        if data == SUFFIX:
            prev_data = SUFFIX
            continue
        else:
            if prev_data == SUFFIX:
                buffer = prev_data + buffer
            prev_data = None
            buffer = data + buffer
    return buffer

def merge_win_path(path, filename):
    if path.endswith('\\') or path.endswith('/'):
        path = path[:len(path)-1]
    return path + '\\' + filename

def extend_key(key, out_len):
    while len(key) < out_len:
        key = key + key
    return key[:out_len]

class R5A_decoder():
    """Decoder for R5A algorithm"""

    def __init__(self, f_path, data):
        self.f_path = f_path
        self.data = bytearray(data)
        self.size = len(data)
        self.quarter_size = self.size >> 2
        self.half_size = self.quarter_size * 2

    def decode(self, r5a_key, key_len):
        for i in (0,1):
            self.loop2(i)
            self.loop1(i)
        path_key = extend_key(self.f_path, key_len)
        hard_key = extend_key(r5a_key, key_len)
        self.data = decode(self.data, bytearray(path_key))
        self.data = decode(self.data, bytearray(hard_key))
        return self.data

    def loop2(self, index2):
        #process quarter of the content
        my_quarter = self.half_size * index2 + self.quarter_size
        end_quarter = my_quarter + self.quarter_size
        for i in range(my_quarter, my_quarter + self.quarter_size):
            dx = i % 255
            self.data[i] = self.data[i] ^ dx
        return self.data

    def loop1(self, index2):
        #process quarter of the content
        my_quarter = self.half_size * index2
        other_quarter = my_quarter + self.quarter_size
        for i in range(0, self.quarter_size):
            other_val = self.data[other_quarter + i]
            my_val = self.data[my_quarter + i]
            self.data[my_quarter + i] = my_val ^ other_val
        return self.data

def decode_content(fp, is_r4a, fname_key, orig_file_name, path=None, r5a_key=None, r5a_keylen=None):
    suffix_len = len(orig_file_name) + len('**') + len('\x0a') + 1
    data = read_encrypted(fp, suffix_len)
    if is_r4a:
        return decode(bytearray(data), bytearray(fname_key))

    if (path is None):
        print "[-] R5A cannot be recover without knowing file's original path"
        return None
    f_path = merge_win_path(str(path), str(orig_file_name))
    print f_path
    r5a_decoder = R5A_decoder(f_path, data)
    return r5a_decoder.decode(r5a_key, r5a_keylen)

def read_encrypted(filep, suffix_len):
    filep.seek(0, os.SEEK_END)
    size = filep.tell()
    if size < suffix_len:
        return None
    filep.seek(0, os.SEEK_SET)
    data = filep.read(1)
    if data != PREFIX:
        print "encrypted not found"
        return None
    return filep.read(size - suffix_len)

def main():
    parser = argparse.ArgumentParser(description="Data XOR")
    parser.add_argument('--file', dest="file", default=None, help="Input file", required=True)
    parser.add_argument('--path', dest='path', default=None, help="Original path - is neccessery to recover R5A")
    args = parser.parse_args()
    
    fp = open(args.file, 'rb')
    fname = search_suffix(fp)
    if fname == None or len(fname) == 0:
        print "Failed to recover file name"
        exit (-1)

    is_r4a = False
    if args.file.endswith("R5A"):
        fname_key = FNAME_KEY_R5A
        print "R5A"
    else:
        fname_key = FNAME_KEY_R4A
        is_r4a = True
        print "R4A"

    orig_file_name = str(decode(bytearray(fname), bytearray(fname_key)))
    print "[+] Original name: " + orig_file_name

    dirname = os.path.dirname(args.file)
    orig_fname = os.path.join(dirname, orig_file_name)

    r5a_key = FNAME_KEY_R5A
    r5a_keylen = len(r5a_key)
    print "[+] Using R5A key length: %s" % r5a_keylen
    
    outdata = decode_content(fp, is_r4a, fname_key, orig_file_name, args.path, r5a_key, r5a_keylen)
    if outdata is None:
        print "[-] Decoding failed"
        return (-2)

    with open(str(orig_fname), 'wb') as outfile:
        outfile.write(outdata)
        print "[+] Decoded to: " + orig_fname
        return 0
    print "[-] Failed writing file"
    return (-1)

if __name__ == "__main__":
    main()

