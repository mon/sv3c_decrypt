# sv3c_decrypt

Decrypter/encrypter for SDVX E-AMUSE CLOUD. Useful to edit resource files
for English translations, for example.

As filenames are obfuscated as a hash, you cannot simply browse the filesystem,
you must know the filenames. As a convenience, I have included a list of most
filenames used. There are only 9 files with an unknown name.

Tested working as of the SV3C beta - keys may change with the final release.

### Setup:
`pip install python-camellia tqdm`

Additionally for Python 2:  
`pip install future`

I hope the code is self explanatory.