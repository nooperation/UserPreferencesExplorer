#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <unordered_map>

#include "../UserPreferences.Shared/Encryption.h"
#include "../UserPreferences.Shared/Common.h"

#include "../UserPreferences.Shared/Encryption.cpp"
#include "../UserPreferences.Shared/Common.cpp"

TEST_CASE("Encryption")
{
    const auto guid = std::string("01234567-89ab-cdef-0123-456789abcdef");
    const auto salt = std::string("6E3F032949637D2E");
    const auto plaintext = std::string("{\"username\":\"example@example.com\",\"refresh_token\":\"\",\"scope_string\":\"\"}");
    const auto ciphertext = std::vector<uint8_t>{
        0x80, 0x19, 0xD3, 0xEC, 0x72, 0x59, 0xA7, 0x5C, 0xC6, 0xDF, 0xF9, 0xBE,
        0x09, 0x51, 0xF8, 0x7C, 0x02, 0x7F, 0x4F, 0x63, 0x72, 0xCA, 0x02, 0xB0,
        0x32, 0xD5, 0x86, 0x6B, 0x68, 0x04, 0xC9, 0xD6, 0x7D, 0xFB, 0xBA, 0x39,
        0x11, 0x46, 0x1C, 0xF6, 0xE4, 0x94, 0xD3, 0xD8, 0xFD, 0xE2, 0x9B, 0x52,
        0x71, 0x89, 0xBB, 0x6C, 0x45, 0xF9, 0x87, 0x37, 0xF7, 0x4D, 0xCC, 0x15,
        0x17, 0xDC, 0x64, 0x6E, 0x72, 0x0F, 0x65, 0xB7, 0xC0, 0x65, 0x6F, 0xB9,
        0xBC, 0xB3, 0x04, 0x0D, 0xE5, 0x88, 0xAF, 0x5B
    };

    SECTION("Encrypt")
    {
        auto data_to_encrypt = std::vector<uint8_t>(plaintext.begin(), plaintext.end());
        data_to_encrypt.push_back('\0');

        auto result = UserPreferences::Encryption::EncryptData(data_to_encrypt, guid, salt);

        REQUIRE(result == ciphertext);
    }

    SECTION("Decrypt")
    {
        auto result = UserPreferences::Encryption::DecryptData(ciphertext, guid, salt);
        auto result_string = std::string(result.begin(), result.end() - 1);

        REQUIRE(result_string == plaintext);
    }
}
