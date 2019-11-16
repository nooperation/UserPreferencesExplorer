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
    const auto plaintext = std::string("Hello World");// std::string("{\"username\":\"example@example.com\",\"refresh_token\":\"\",\"scope_string\":\"\"}");
    const auto ciphertext = std::vector<uint8_t>{
        0x6a, 0x0f, 0xb1, 0xca, 0x3b, 0x60, 0x63, 0x04, 0x2c, 0x16, 0x92, 0xa2, 0x6e, 0x40, 0x71, 0x02
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
