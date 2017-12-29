#!/usr/bin/python2.7
"Decodes AES encrypted modules of TrickBot"

__AUTHOR__ = 'hasherezade'

import argparse
import hashlib
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def hash_rounds(data_buf):
    while len(data_buf) <= 0x1000:
        buf_hash = hashlib.sha256(data_buf).digest()
        data_buf += buf_hash
    return buf_hash

def aes_decrypt(data):
    key = hash_rounds(data[:0x20])[:0x20]
    iv = hash_rounds(data[0x10:0x30])[:0x10]
    aes = AES.new(key, AES.MODE_CBC, iv)
    data = pad(data[0x30:])
    return aes.decrypt(data)

def find_pe(data):
    while len(data):
        mz_start = data.find('MZ')
        if mz_start == -1:
            return None
        pe_start = data[mz_start:]
        data = data[mz_start + len('MZ'):]
        pe = data.find('PE')
        if pe != -1:
            return pe_start
    return None

def dump_to_file(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

def main():
    parser = argparse.ArgumentParser(description="TrickBot AES decoder")
    parser.add_argument('--datafile',dest="datafile",default=None,help="File with data", required=True)
    parser.add_argument('--outfile',dest="outfile",default="out.bin", help="Where to dump the output", required=False)
    parser.add_argument('--pe_name',dest="pe_name",default="trick_module.dll", help="Where to dump the PE", required=False)
    args = parser.parse_args()

    data = open(args.datafile, 'rb').read()
    data_len = len(data)

    output = aes_decrypt(data)
    print len(output)
    
    if output is None:
        print "Output is empty"
        return
        
    if args.outfile is not None:
        dump_to_file(args.outfile, output)
        print "Dumped decoded to: %s" % (args.outfile)
    else:
        print output
        return

    pe_data = find_pe(output)
    if pe_data is None:
        return

    dump_to_file(args.pe_name, pe_data)
    print "Extracted Module to: %s" % (args.pe_name)
    return

if __name__ == '__main__':
    main()
