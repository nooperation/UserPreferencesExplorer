#include <vector>
#include <Windows.h>
#include <fstream>

#include "Utils.h"

namespace Utils
{
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

        return std::string(machine_guid.begin(), machine_guid.end() - 1);
    }

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
}
