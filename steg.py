from PIL import Image
import numpy as np
import os
import argparse
import sys

HEADER_LEN_BYTES = 8  # 8 байт для хранения размера (uint64 little-endian)

def hide_encrypted_exe_in_image(encrypted_exe_path: str, image_path: str, output_image_path: str) -> None:
    """
    Скрывает payload в изображении, предваряя 8-байтным заголовком (little-endian uint64 length).
    Биты упакованы MSB-first внутри каждого байта (np.unpackbits(..., bitorder='big')).
    Сохраняйте результат в PNG (lossless).
    """
    if not os.path.exists(encrypted_exe_path):
        raise FileNotFoundError(encrypted_exe_path)
    if not os.path.exists(image_path):
        raise FileNotFoundError(image_path)

    with open(encrypted_exe_path, "rb") as f:
        payload = f.read()
    payload_len = len(payload)

    header = payload_len.to_bytes(HEADER_LEN_BYTES, "little")
    full = header + payload

    # Биты: для каждого байта — MSB..LSB
    data_bits = np.unpackbits(np.frombuffer(full, dtype=np.uint8), bitorder='big')

    img = Image.open(image_path).convert("RGBA")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.ravel()

    if data_bits.size > flat.size:
        raise ValueError(f"Изображение слишком маленькое: нужно {data_bits.size} бит, доступно {flat.size} бит")

    # Подменяем младшие биты
    flat[:data_bits.size] = (flat[:data_bits.size] & 0xFE) | data_bits

    stego = flat.reshape(arr.shape)
    os.makedirs(os.path.dirname(output_image_path) or ".", exist_ok=True)
    Image.fromarray(stego, "RGBA").save(output_image_path, "PNG")

    print(f"[hide] payload {payload_len} bytes, header {HEADER_LEN_BYTES} bytes, used bits {data_bits.size}, capacity {flat.size}")

def extract_encrypted_exe_from_image_python(stego_image_path: str, output_exe_path: str) -> bytes:
    """
    Извлекает payload из стего-картинки, ожидая 8-байтный заголовок (little-endian uint64 length).
    Возвращает payload bytes и записывает в output_exe_path.
    """
    img = Image.open(stego_image_path).convert("RGBA")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.ravel()

    if flat.size < HEADER_LEN_BYTES * 8:
        raise ValueError("Image too small to contain header")

    # Читаем header: по 8 LSB -> байт (MSB-first внутри байта)
    header_bytes = bytearray(HEADER_LEN_BYTES)
    for i in range(HEADER_LEN_BYTES):
        bits = flat[i*8:(i+1)*8]
        byte = 0
        for j, bit in enumerate(bits):
            byte |= (int(bit & 1) << (7 - j))
        header_bytes[i] = byte

    payload_len = int.from_bytes(header_bytes, "little")
    needed_bits = (HEADER_LEN_BYTES + payload_len) * 8
    if needed_bits > flat.size:
        raise ValueError(f"Not enough capacity: needed {needed_bits} bits, have {flat.size} bits")

    payload_bits = flat[HEADER_LEN_BYTES*8 : HEADER_LEN_BYTES*8 + payload_len*8]
    payload = bytearray(payload_len)
    for i in range(payload_len):
        bits = payload_bits[i*8:(i+1)*8]
        byte = 0
        for j, bit in enumerate(bits):
            byte |= (int(bit & 1) << (7 - j))
        payload[i] = byte

    with open(output_exe_path, "wb") as f:
        f.write(payload)

    print(f"[extract] payload_len={payload_len}, wrote: {output_exe_path}")
    return bytes(payload)

def extract_encrypted_exe_from_image(stego_image_path, output_exe_path):
    """
    Извлекает зашифрованный EXE-файл из изображения, читая сначала 8-байтовый заголовок
    с размером payload, затем извлекая payload.
    """
    try:
        if not os.path.exists(stego_image_path):
            raise FileNotFoundError(f"Изображение {stego_image_path} не найдено")
        img = Image.open(stego_image_path).convert('RGBA')
        img_array = np.array(img, dtype=np.uint8)

        flat = img_array.flatten().astype(np.uint8)

        # Сначала читаем HEADER_LEN_BYTES * 8 бит, чтобы получить длину payload
        header_bits_count = HEADER_LEN_BYTES * 8
        if flat.size < header_bits_count:
            raise ValueError("Изображение слишком маленькое — не хватает бит для чтения заголовка")

        header_bits = flat[:header_bits_count] & 1
        header_bytes = np.packbits(header_bits).tobytes()
        payload_len = int.from_bytes(header_bytes[:HEADER_LEN_BYTES], byteorder='little')

        total_bits_needed = (HEADER_LEN_BYTES + payload_len) * 8
        if total_bits_needed > flat.size:
            raise ValueError(f"В изображении недостаточно места: нужно {total_bits_needed} бит, доступно {flat.size} бит")

        # Теперь читаем все биты заголовка+payload
        payload_bits = flat[:total_bits_needed] & 1
        payload_bytes = np.packbits(payload_bits).tobytes()

        # Первые HEADER_LEN_BYTES байт — заголовок, остальное — payload
        extracted_payload = payload_bytes[HEADER_LEN_BYTES:HEADER_LEN_BYTES + payload_len]

        out_dir = os.path.dirname(output_exe_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_exe_path, 'wb') as f:
            f.write(extracted_payload)

        print(f"Успешно извлечено {payload_len} байт в {output_exe_path}")

    except Exception as e:
        print(f"Ошибка при извлечении данных: {e}")
        raise

def parse_args():
    parser = argparse.ArgumentParser(description="LSB стеганография: скрыть/извлечь зашифрованный EXE в/из изображения (header с размером встроен автоматически)")
    parser.add_argument('--payload', '--encrypted-exe', dest='payload', default='encrypted_payload/payload.txt',
                        help='Путь к зашифрованному (файл для встраивания). По умолчанию: encrypted_payload/payload.txt')
    parser.add_argument('--original-image', default='input_images/img_big.jpg',
                        help='Путь к входному изображению (для встраивания).')
    parser.add_argument('--stego-image', default='images_with_payload/image.png',
                        help='Путь к выходному стего-изображению (PNG).')
    parser.add_argument('--extracted-exe', default='ExtractedData/reverse_shell_tls.exe',
                        help='Путь для извлечённого EXE (при извлечении).')
    parser.add_argument('--extract', action='store_true',
                        help='Если указан — выполняет извлечение вместо встраивания. При извлечении data-size не нужен.')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    try:
        if args.extract:
            # режим извлечения — не требует data-size, потому что размер читается из заголовка
            extract_encrypted_exe_from_image(args.stego_image, args.extracted_exe)
        else:
            # режим встраивания
            if not os.path.exists(args.payload):
                print(f"Файл для встраивания не найден: {args.payload}")
                sys.exit(2)
            enc_size = os.path.getsize(args.payload)
            print(f"Размер внедряемого файла: {enc_size} байт")
            hide_encrypted_exe_in_image(args.payload, args.original_image, args.stego_image)

    except Exception as e:
        print("Завершено с ошибкой.")
        sys.exit(3)
