from builtins import bytes
from os.path import basename, dirname, exists
import os
import errno
from struct import pack, unpack
import hashlib

import camellia
from tqdm import tqdm

def xor(data, key):
    data = bytearray(data)
    key = bytearray(key)
    for i in range(len(data)):
        data[i] ^= key[i]
    return data

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def generate_keys(path):
    salt = '5dIFp5Nb8n1kyPRSU8dKGyhJHx317PA3'
    keyOffsets = [8, 25, 22, 47, 24,  5, 16,  9, 33,  3, 45,  1, 30, 34, 37, 36,
                  15, 39, 11, 14, 23, 29, 26, 40, 31,  7, 13, 38, 27, 17, 12, 21]
    ivOffsets  = [28, 19, 2,  46, 4,  20, 18, 41, 32, 43, 0,  6,  44, 10, 35, 42]
    filename = basename(path)

    toHash = salt + filename + salt + filename
    hashed = bytes(hashlib.sha384(toHash.encode('ASCII')).digest())
    key = [0] * 32
    for offset, i in zip(keyOffsets, range(32)):
        key[i] = hashed[offset]

    iv = bytearray([0]*16)
    for offset, i in zip(ivOffsets, range(16)):
        iv[i] = hashed[offset]
    iv = bytes(iv)

    iv = unpack('<Q', iv[:8])[0] | (unpack('<Q', iv[8:])[0] << 64)

    return key, iv

def obfuscate(path):
    salt = '[oh6|}:?rTf5*8zS'
    strip = ['data', './data', '/data']
    for s in strip:
        if path.startswith(s):
            path = path[len(s):]

    toHash = salt + path
    hashed = hashlib.md5(toHash.encode('ASCII')).hexdigest()
    return 'data/{}/{}/{}/{}'.format(hashed[0], hashed[1], hashed[2], hashed[3:])

def find_missing(base):
    # cd eamuse_cloud
    # find data -type f > obfuscated.txt
    with open('obfuscated.txt','r') as f:
        obfuscated = [x.strip() for x in f.readlines()]

    with open('filelist.txt','r') as f, \
         open('filelist_filtered.txt', 'w') as out, \
         open('filelist_missing.txt','w') as missing:
        for name in f.readlines():
            name = name.strip()
            ob = obfuscate(name)
            path = base + ob
            if exists(path):
                #print "HIT", name
                out.write(name + '\n')
                obfuscated.pop(obfuscated.index(ob))
            else:
                missing.write(name + '\n')
    with open('filelist_unknown.txt','w') as unknown:
        for nope in obfuscated:
            unknown.write(nope + '\n')

class CamelliaCounter():
    def __init__(self, iv):
        self.counter = 0
        self.iv = iv
        self.commonKey = 0x53856E750D645467AE91F2FF0FA28735

    def next(self):
        ctr = self.counter * self.commonKey
        self.counter += 1
        ret = self.iv + ctr
        mask = 0xFFFFFFFFFFFFFFFF # 64 bit
        return pack('<2Q', ret & mask, (ret >> 64) & mask)

    def next_bytes(self, count):
        ret = (self.next() for i in range((count+15) // 16))
        return b''.join(ret)

def decrypt_file(base, path, destination):
    key, iv = generate_keys(path)
    key = bytes(bytearray(key))
    ob = obfuscate(path)

    mkdir_p(dirname(destination))

    with open(base + ob, 'rb') as src:
        crypt = src.read()

    ctr = CamelliaCounter(iv)
    cam = camellia.CamelliaCipher(key=key, mode=camellia.MODE_ECB)
    # generate the entire key at once since bigger inputs run faster
    keyStream = cam.encrypt(ctr.next_bytes(len(crypt)))

    with open(destination, 'wb') as dest:
        dest.write(xor(crypt, keyStream))


if __name__ == '__main__':
    base = 'D:/sdvx/SDVX3_CLOUD/'
    result = base + 'decrypted/'

    with open('filelist.txt') as f:
        for file in tqdm(f.readlines()):
            file = file.strip()
            tqdm.write(file)
            decrypt_file(base, file, result + file)
