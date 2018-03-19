#include "LibUserPreferences.h"

#include "../UserPreferences.Shared/Common.h"
#include "../UserPreferences.Shared/Encryption.h"

DllExport APIResult DecryptData(
    _In_ const uint8_t *encrypted_buffer,
    _In_ size_t encrypted_buffer_size,
    _In_ const char *machine_guid,
    _In_ const char *salt_string,
    _Out_ uint8_t *out_decrypted_buffer,
    _Inout_ size_t *out_decrypted_buffer_size)
{
    if (encrypted_buffer == nullptr || out_decrypted_buffer_size == nullptr)
    {
        return kResult_GeneralFailure;
    }

    std::string guid;
    if (machine_guid == nullptr)
    {
        guid = UserPreferences::Common::GetMachineGuid();
    }
    else
    {
        guid = machine_guid;
    }

    std::string salt;
    if (salt_string == nullptr)
    {
        salt = UserPreferences::Common::GetDefaultSalt();
    }
    else
    {
        salt = salt_string;
    }

    const auto encrypted = std::vector<uint8_t>(&encrypted_buffer[0], &encrypted_buffer[encrypted_buffer_size]);
    const auto decrypted = UserPreferences::Encryption::DecryptData(encrypted, guid, salt);

    if (out_decrypted_buffer == nullptr || *out_decrypted_buffer_size < decrypted.size())
    {
        *out_decrypted_buffer_size = decrypted.size();
        return kResult_BufferTooSmall;
    }

    *out_decrypted_buffer_size = decrypted.size();
    memcpy(out_decrypted_buffer, &decrypted[0], *out_decrypted_buffer_size);
    return kResult_GeneralSuccess;
}

DllExport APIResult EncryptData(
    _In_ const uint8_t *plaintext_data,
    _In_ size_t plaintext_data_size,
    _In_ const char *machine_guid,
    _In_ const char *salt_string,
    _Out_ uint8_t *out_encrypted_buffer,
    _Inout_ size_t *out_encrypted_buffer_size)
{
    if (plaintext_data == nullptr || out_encrypted_buffer_size == nullptr)
    {
        return kResult_GeneralFailure;
    }
    
    std::string guid;
    if (machine_guid == nullptr)
    {
        guid = UserPreferences::Common::GetMachineGuid();
    }
    else
    {
        guid = machine_guid;
    }

    std::string salt;
    if (salt_string == nullptr)
    {
        salt = UserPreferences::Common::GetDefaultSalt();
    }
    else
    {
        salt = salt_string;
    }

    const auto plaintext = std::vector<uint8_t>(&plaintext_data[0], &plaintext_data[plaintext_data_size]);
    const auto encrypted = UserPreferences::Encryption::EncryptData(plaintext, guid, salt);

    if (out_encrypted_buffer == nullptr || *out_encrypted_buffer_size < encrypted.size())
    {
        *out_encrypted_buffer_size = encrypted.size();
        return kResult_BufferTooSmall;
    }

    *out_encrypted_buffer_size = encrypted.size();
    memcpy(out_encrypted_buffer, &encrypted[0], *out_encrypted_buffer_size);
    return kResult_GeneralSuccess;
}
