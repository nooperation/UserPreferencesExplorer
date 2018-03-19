#include <openssl/evp.h>
#include <boost/algorithm/hex.hpp>

#include "../LibUserPreferences/LibUserPreferences.h"
#include "Encryption.h"

#pragma comment(lib, "libeay32")

namespace Encryption
{
    std::vector<uint8_t> DecryptData(
        const std::vector<uint8_t>& encrypted_data,
        const std::string& machine_guid,
        const std::string& salt_string)
    {
        return EncryptOrDecryptData(encrypted_data, machine_guid, salt_string, false);
    }

    std::vector<uint8_t> EncryptData(
        const std::vector<uint8_t>& plaintext_data,
        const std::string& machine_guid,
        const std::string& salt_string)
    {
        return EncryptOrDecryptData(plaintext_data, machine_guid, salt_string, true);
    }
}
