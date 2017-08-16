#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <Windows.h>

#include <openssl/evp.h>
#include <boost/algorithm/hex.hpp>
#include <boost/program_options.hpp>

#pragma comment(lib, "libeay32")

/// <summary>
/// Reads all bytes from the specified path.
/// </summary>
/// <param name="path">Path to the file to read.</param>
/// <returns>Container of sequential bytes or empty container on error.</returns>
std::vector<uint8_t> ReadAllBytes(const std::string &path)
{
    std::ifstream inStream(path, std::ios::binary | std::ios::ate);
    auto fileSize = static_cast<size_t>(inStream.tellg());
    if (fileSize == 0)
    {
        throw std::exception("File is empty");
    }

    auto fileBytes = std::vector<uint8_t>(fileSize);

    inStream.seekg(0, std::ios::beg);
    inStream.read(reinterpret_cast<char *>(&fileBytes[0]), fileSize);
    inStream.close();

    return fileBytes;
}

/// <summary>
/// Decrypts the specified cipherText into <paramref name="out_plaintext"/>
/// using the given key and initialization vector.
/// </summary>
/// <param name="cipherText">Encrypted bytes to decrypt.</param>
/// <param name="key">Key used for decryption.</param>
/// <param name="initialization_vector">Initialization vector used for decryption.</param>
/// <param name="out_plaintext">[out] Decrypted bytes.</param>
/// <returns>True on success.</returns>
std::vector<uint8_t> Decrypt(
    const std::vector<uint8_t> &cipherText,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &initialization_vector)
{
    auto out_plaintext = std::vector<uint8_t>(cipherText.size());
    auto plaintext_length = 0;
    auto cipher = EVP_aes_256_cbc();
    auto ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);

    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, &key[0], &initialization_vector[0]))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::exception("EVP_DecryptInit_ex - FAILED");
    }

    if(!EVP_DecryptUpdate(ctx, &out_plaintext[0], &plaintext_length, &cipherText[0], static_cast<int>(cipherText.size())))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::exception("EVP_DecryptUpdate - FAILED");
    }

    auto additional_length = 0;
    if (!EVP_DecryptFinal_ex(ctx, &out_plaintext[plaintext_length], &additional_length))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::exception("EVP_DecryptFinal_ex - FAILED");
    }

    out_plaintext.resize(plaintext_length + additional_length);
    EVP_CIPHER_CTX_free(ctx);
    return out_plaintext;
}

/// <summary>
/// Generates a key and initialization_vector out of the specified salt and source bytes.
/// </summary>
/// <param name="salt">Salt bytes used to generate the key and initialization vector.</param>
/// <param name="source_bytes">Source bytes used to generate the key and initialization vector.</param>
/// <param name="out_key">[out] Generated key.</param>
/// <param name="out_initialization_vector">[out] Generated initialization vector.</param>
/// <returns>True on success.</returns>
void GetKeys(
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

    auto derived_key_length = EVP_BytesToKey(
        cipher,
        md,
        &salt[0],
        &source_bytes[0],
        static_cast<int>(source_bytes.size()),
        kIterationCount,
        &out_key[0],
        &out_initialization_vector[0]
    );

    if (derived_key_length == 0)
    {
        throw std::exception("EVP_BytesToKey - Failed to generate key");
    }
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
            mangled_data[index] = static_cast<uint8_t>(mangled_character);
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
        throw std::exception("RegOpenKeyEx - FAILED");
    }

    DWORD buff_size = 0;
    result = RegQueryValueExA(key_handle, kMachineGuidName.c_str(), nullptr, nullptr, nullptr, &buff_size);
    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(key_handle);
        throw std::exception("RegQueryValueEx - FAILED");
    }

    auto machine_guid = std::vector<uint8_t>(buff_size);
    result = RegQueryValueExA(key_handle, kMachineGuidName.c_str(), nullptr, nullptr, &machine_guid[0], &buff_size);
    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(key_handle);
        throw std::exception("RegQueryValueEx - FAILED");
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
    auto required_path_length = GetEnvironmentVariableA(kEnvironmentVariable.c_str(), reinterpret_cast<LPSTR>(&path[0]), 0);
    path.resize(required_path_length);

    // Get the actual environment variable
    GetEnvironmentVariableA(kEnvironmentVariable.c_str(), reinterpret_cast<LPSTR>(&path[0]), static_cast<DWORD>(path.size()));

    // GetEnvironmentVariableA will add a null character in at the end, exclude it
    auto local_app_data_path = std::string(path.begin(), path.end() - 1);

    return local_app_data_path + kDefaultUserPreferencesPath;
}


/// <summary>
/// Decrypts the specified encrypted user preferences file
/// </summary>
/// <param name="file_path">Path to the encrypted UserPreferences.bag</param>
/// <param name="machine_guid">Machine GUID used to encrypt the UserPreferences.bag</param>
/// <param name="salt_string">Salt used to encrypt UserPreferences.bag</param>
/// <returns>Decrypted user preferences</returns>
std::string DecryptUserPreferences(const std::string& file_path, const std::string& machine_guid, const std::string& salt_string)
{
    std::vector<uint8_t> salt_bytes;
    boost::algorithm::unhex(salt_string.begin(), salt_string.end(), std::back_inserter(salt_bytes));

    auto machine_guid_bytes = std::vector<uint8_t>(machine_guid.begin(), machine_guid.end() - 1);
    auto mangled_data = MangleData(machine_guid_bytes);

    std::vector<uint8_t> key;
    std::vector<uint8_t> initialization_vector;
    GetKeys(salt_bytes, mangled_data, key, initialization_vector);

    auto cipher_text = ReadAllBytes(file_path);
    auto plaintext = Decrypt(cipher_text, key, initialization_vector);

    return std::string(plaintext.begin(), plaintext.end());
}

int main(int argc, char* argv[])
{
    namespace po = boost::program_options;
    static const auto kSalt = std::string("6E3F032949637D2E");

    try
    {
        auto arg_salt = po::value<std::string>()->default_value(kSalt, "");
        auto arg_guid = po::value<std::string>()->default_value(GetMachineGuid(), "");
        auto arg_path = po::value<std::string>()->default_value(GetPathToUserPreferencesBag(), "");

        auto commandline_descriptions = po::options_description("Arguments");
        commandline_descriptions.add_options()
            ("help", "Help")
            ("salt", arg_salt, "Salt used for key generation.")
            ("guid", arg_guid, "GUID used for key generation.")
            ("path", arg_path, "Path to the UserPreferences.bag to decrypt.");

        auto parsed_options = po::parse_command_line(argc, argv, commandline_descriptions);
        po::variables_map vm;
        po::store(parsed_options, vm);
        po::notify(vm);

        if (vm.count("help"))
        {
            std::cout << commandline_descriptions << std::endl;
            return EXIT_SUCCESS;
        }

        auto decrypted_preferences = DecryptUserPreferences(
            vm["path"].as<std::string>(),
            vm["guid"].as<std::string>(),
            vm["salt"].as<std::string>()
        );

        std::cout << decrypted_preferences << std::endl;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Failed to decrypt user preferences: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
