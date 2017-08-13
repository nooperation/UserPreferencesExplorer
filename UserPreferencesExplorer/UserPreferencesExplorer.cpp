#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <Windows.h>

#pragma comment(lib, "libeay32")

/// <summary>
/// Reads all bytes from the specified path.
/// </summary>
/// <param name="path">Path to the file to read.</param>
/// <returns>Container of sequential bytes or empty container on error.</returns>
std::vector<uint8_t> ReadAllBytes(const std::string &path)
{
    try
    {
        std::ifstream inStream(path, std::ios::binary | std::ios::ate);
        auto fileSize = (size_t)inStream.tellg();
        auto fileBytes = std::vector<uint8_t>(fileSize);

        inStream.seekg(0, std::ios::beg);
        inStream.read((char *)&fileBytes[0], fileSize);
        inStream.close();

        return fileBytes;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Failed to read file '" << path << "' - " << ex.what() << std::endl;
        return std::vector<uint8_t>();
    }
}

/// <summary>
/// Decrypts the specified cipherText into <paramref name="out_plaintext"/> using the given key and initialization vector.
/// </summary>
/// <param name="cipherText">Encrypted bytes to decrypt.</param>
/// <param name="key">Key used for decryption.</param>
/// <param name="initialization_vector">Initialization vector used for decryption.</param>
/// <param name="out_plaintext">[out] Decrypted bytes.</param>
/// <returns>True on success.</returns>
bool Decrypt(
    const std::vector<uint8_t> &cipherText,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &initialization_vector,
    std::vector<uint8_t> &out_plaintext)
{
    out_plaintext.resize(cipherText.size());
    int plaintext_length = 0;

    auto cipher = EVP_aes_256_cbc();
    auto ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);

    auto is_successful = EVP_DecryptInit_ex(ctx, cipher, nullptr, &key[0], &initialization_vector[0]);
    if (is_successful == false)
    {
        std::cerr << "EVP_DecryptInit_ex - FAILED" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    is_successful = EVP_DecryptUpdate(ctx, &out_plaintext[0], &plaintext_length, &cipherText[0], (int)cipherText.size());
    if (is_successful == false)
    {
        std::cerr << "EVP_DecryptUpdate - FAILED" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    auto additional_length = 0;
    is_successful = EVP_DecryptFinal_ex(ctx, &out_plaintext[plaintext_length], &additional_length);
    if (is_successful == false)
    {
        std::cerr << "EVP_DecryptFinal_ex - FAILED" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    out_plaintext.resize(plaintext_length + additional_length);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/// <summary>
/// Generates a key and initialization_vector out of the specified salt and source bytes.
/// </summary>
/// <param name="salt">Salt bytes used to generate the key and initialization vector.</param>
/// <param name="source_bytes">Source bytes used to generate the key and initialization vector.</param>
/// <param name="out_key">[out] Generated key.</param>
/// <param name="out_initialization_vector">[out] Generated initialization vector.</param>
/// <returns>True on success.</returns>
bool GetKeys(
    const std::vector<uint8_t> &salt,
    const std::vector<uint8_t> &source_bytes,
    std::vector<uint8_t> &out_key,
    std::vector<uint8_t> &out_initialization_vector)
{
    static const int kIterationCount = 5;

    auto cipher = EVP_aes_256_cbc();
    auto md = EVP_sha1();

    out_key.resize(cipher->key_len);
    out_initialization_vector.resize(cipher->iv_len);

    auto result = EVP_BytesToKey(cipher, md, &salt[0], &source_bytes[0], (int)source_bytes.size(), kIterationCount, &out_key[0], &out_initialization_vector[0]);
    return result > 0;
}

/// <summary>
/// Mangles data for use as source bytes when generating a key and initialization vector.
/// </summary>
/// <param name="data_to_mangle">Bytes to mangle.</param>
/// <returns>Collection of mangled bytes.</returns>
std::vector<uint8_t> MangleData(const std::vector<uint8_t> &data_to_mangle)
{
    auto mangled_data = std::vector<uint8_t>(data_to_mangle);
    const auto kMangledDataSize = mangled_data.size();

    for(size_t index = 0; index < kMangledDataSize; ++index)
    {
        auto mangled_character = ((index + 2) * mangled_data[index]) % 128;
        if (mangled_character != 0)
        {
            mangled_data[index] = (uint8_t)mangled_character;
        }
    }

    return mangled_data;
}

/// <summary>
/// Gets the machine GUID.
/// </summary>
/// <returns>The machine GUID on success or an empty string on failure.</returns>
std::string GetMachineGuid()
{
    static const auto kMachineGuidPath = std::string("SOFTWARE\\Microsoft\\Cryptography");
    static const auto kMachineGuidName = std::string("MachineGuid");

    HKEY key_handle;

    auto result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, kMachineGuidPath.c_str(), NULL, KEY_READ | KEY_WOW64_64KEY, &key_handle);
    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(key_handle);
        std::cerr << "RegOpenKeyEx - FAILED" << std::endl;
        return "";
    }

    DWORD buff_size = 0;
    result = RegQueryValueExA(key_handle, kMachineGuidName.c_str(), nullptr, nullptr, nullptr, &buff_size);
    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(key_handle);
        std::cerr << "RegQueryValueEx - FAILED\n" << std::endl;
        return "";
    }

    auto machine_guid = std::vector<uint8_t>(buff_size);
    result = RegQueryValueExA(key_handle, kMachineGuidName.c_str(), nullptr, nullptr, &machine_guid[0], &buff_size);
    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(key_handle);
        std::cerr << "RegQueryValueEx - FAILED\n" << std::endl;
        return "";
    }

    RegCloseKey(key_handle);

    return std::string(machine_guid.begin(), machine_guid.end());
}

/// <summary>
/// Gets the path to the user's UserPreferences.bag.
/// </summary>
/// <returns>Path to the user's UserPreferences.bag.</returns>
std::string GetPathToUserPreferencesBag()
{
    static const auto kDefaultUserPreferencesPath = std::string("\\LindenLab\\SansarClient\\UserPreferences.bag");
    static const auto kEnvironmentVariable = std::string("localappdata");

    // Resize our container to hold the environment variable
    std::vector<int8_t> path(1);
    auto required_path_length = GetEnvironmentVariableA(kEnvironmentVariable.c_str(), (LPSTR)&path[0], 0);
    path.resize(required_path_length);

    // Get the actual environment variable
    GetEnvironmentVariableA(kEnvironmentVariable.c_str(), (LPSTR)&path[0], (DWORD)path.size());

    // GetEnvironmentVariableA will add a null character in at the end, exclude it
    auto local_app_data_path = std::string(path.begin(), path.end() - 1);

    return local_app_data_path + kDefaultUserPreferencesPath;
}

int main(int argc, char* argv[])
{
    // The salt is hardcoded
    static const std::vector<uint8_t> kSalt {
        0x6E, 0x3F, 0x03, 0x29, 0x49, 0x63, 0x7D, 0x2E
    };

    auto machine_guid = GetMachineGuid();
    if (machine_guid.empty())
    {
        std::cerr << "Failed to get MachineGuid" << std::endl;
        return 0;
    }

    auto machine_guid_bytes = std::vector<uint8_t>(machine_guid.begin(), machine_guid.end() - 1);
    auto mangled_data = MangleData(machine_guid_bytes);

    std::vector<uint8_t> key;
    std::vector<uint8_t> initialization_vector;
    if (!GetKeys(kSalt, mangled_data, key, initialization_vector))
    {
        std::cerr << "Failed to generate keys" << std::endl;
        return EXIT_FAILURE;
    }

    std::string path_to_decrypt;
    if (argc == 2)
    {
        path_to_decrypt = std::string(argv[1]);
    }
    else
    {
        path_to_decrypt = GetPathToUserPreferencesBag();
    }

    auto cipher_text = ReadAllBytes(path_to_decrypt);
    if (cipher_text.empty())
    {
        std::cerr << "ReadAllBytes - FAILED" << std::endl;
        return EXIT_FAILURE;
    }

    auto plaintext = std::vector<uint8_t>(cipher_text.size());
    if (!Decrypt(cipher_text, key, initialization_vector, plaintext))
    {
        std::cerr << "Decrypt - FAILED" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << &plaintext[0] << std::endl;

    return EXIT_SUCCESS;
}
