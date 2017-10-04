from builtins import bytes
from os.path import basename, dirname, exists, join
import os
import errno
from struct import pack, unpack
import hashlib
import time

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

def deobfuscate(obPath, filelist):
    with open(filelist, 'r') as f:
        files = [l.strip() for l in f.readlines()]

    for f in files:
        if obfuscate(f) == obPath:
            return f
    return None

def find_missing(base):
    # what's in there at the moment
    obfuscated = []
    dataDir = join(base, 'data')
    for dir_, _, files in os.walk(dataDir):
        for fileName in files:
            relDir = os.path.relpath(dir_, base)
            relFile = os.path.join(relDir, fileName)
            # consistency
            relFile = relFile.replace('\\', '/')
            obfuscated.append(relFile)

    # what do we know
    with open('filelist.txt','r') as f, \
         open('filelist_missing.txt','w') as missing:
        for name in f.readlines():
            name = name.strip()
            ob = obfuscate(name)
            path = join(base,ob)
            if exists(path):
                #print "HIT", name, ob
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

def crypt_file(source, dest, key, iv):
    key = bytes(bytearray(key))
    mkdir_p(dirname(dest))

    with open(source, 'rb') as src:
        crypt = src.read()

    ctr = CamelliaCounter(iv)
    cam = camellia.CamelliaCipher(key=key, mode=camellia.MODE_ECB)
    # generate the entire key at once since bigger inputs run faster
    keyStream = cam.encrypt(ctr.next_bytes(len(crypt)))

    with open(dest, 'wb') as dest:
        dest.write(xor(crypt, keyStream))

def encrypt_file(sourceDir, path, destDir):
    '''encrypt_file('install_dir_decrypted', '/data/others/music_db.xml', 'install_dir')'''

    key, iv = generate_keys(path)
    ob = obfuscate(path)

    crypt_file(join(sourceDir, path), join(destDir, ob), key, iv)

def decrypt_file(sourceDir, path, destDir):
    '''decrypt_file('install_dir', '/data/others/music_db.xml', 'install_dir_decrypted')'''

    key, iv = generate_keys(path)
    ob = obfuscate(path)

    crypt_file(join(sourceDir, ob), join(destDir, path), key, iv)


if __name__ == '__main__':
    sourceDir = 'D:/sdvx/EAMUSE_CLOUD'
    destDir = join(sourceDir, 'decrypted')

    with open('filelist.txt') as f:
        for file in tqdm(f.readlines()):
            file = file.strip()
            #if exists(join(sourceDir, obfuscate(file))):
            #    print file
            if not exists(join(destDir, file)):
                tqdm.write(file)
                decrypt_file(sourceDir, file, destDir)
