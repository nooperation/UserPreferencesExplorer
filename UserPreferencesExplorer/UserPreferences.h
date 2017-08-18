#pragma once

#include <vector>
#include <string>

namespace Encryption
{
    /// <summary>
    /// Decrypts encrypted data
    /// </summary>
    /// <param name="encrypted_data">Encrypted data</param>
    /// <param name="machine_guid">Machine GUID used to encrypt data</param>
    /// <param name="salt_string">Salt used to encrypt data</param>
    /// <returns>Decrypted data</returns>
    std::vector<uint8_t> DecryptData(
        const std::vector<uint8_t>& encrypted_data,
        const std::string& machine_guid,
        const std::string& salt_string);

    /// <summary>
    /// Encrypts data
    /// </summary>
    /// <param name="encrypted_data">Data to encrypt</param>
    /// <param name="machine_guid">Machine GUID used to encrypt data</param>
    /// <param name="salt_string">Salt used to encrypt data</param>
    /// <returns>Decrypted data</returns>
    std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& plaintext_data,
        const std::string& machine_guid,
        const std::string& salt_string);
};
