#pragma once
#define DllExport   __declspec( dllexport ) 

#include <sal.h>
#include <cstdint>

extern "C"
{
    enum APIResult {
        kResult_GeneralSuccess = 0,
        kResult_GeneralFailure = -1,
        kResult_BufferTooSmall = -2
    };

    /// <summary>
    /// Decrypts encrypted data
    /// </summary>
    /// <param name="encrypted_buffer">Encrypted bytes buffer to decrypt</param>
    /// <param name="encrypted_buffer_size">Encrypted bytes buffer size in bytes</param>
    /// <param name="machine_guid">Optional machine GUID. Defaults to current machine GUID if not supplied.</param>
    /// <param name="salt_string">Optional salt. Defaults to last known salt if not supplied.</param>
    /// <param name="out_decrypted_buffer">Optional decrypted buffer</param>
    /// <param name="out_encrypted_buffer_size">Decrypted buffer size in bytes. Will be set to the required size if decrypted buffer is NULL. </param>
    /// <returns>
    /// kResult_GeneralSuccess on success.
    /// kResult_BufferTooSmall if decrypted buffer size is too small or decrypted buffer was not provided.
    /// kResult_GeneralFailure on failure.
    ///</returns>
    DllExport APIResult DecryptData(
        _In_ const uint8_t *encrypted_buffer,
        _In_ size_t encrypted_buffer_size,
        _In_opt_ const char *machine_guid,
        _In_opt_ const char *salt_string,
        _Out_opt_ uint8_t *out_decrypted_buffer,
        _Inout_ size_t *out_decrypted_buffer_size
    );

    /// <summary>
    /// Encrypts data
    /// </summary>
    /// <param name="plaintext_data">Plaintext to enctypt</param>
    /// <param name="plaintext_data_size">Plaintext size in bytes</param>
    /// <param name="machine_guid">Optional machine GUID. Defaults to current machine GUID if not supplied.</param>
    /// <param name="salt_string">Optional salt. Defaults to last known salt if not supplied.</param>
    /// <param name="out_encrypted_buffer">Optional enctypted buffer</param>
    /// <param name="out_encrypted_buffer_size">Encrypted buffer size in bytes. Will be set to the required size if enctypted buffer is NULL. </param>
    /// <returns>
    /// kResult_GeneralSuccess on success.
    /// kResult_BufferTooSmall if encrypted buffer size is too small or encrypted buffer was not provided.
    /// kResult_GeneralFailure on failure.
    ///</returns>
    DllExport APIResult EncryptData(
        _In_ const uint8_t *plaintext_data,
        _In_ size_t plaintext_data_size,
        _In_opt_ const char *machine_guid,
        _In_opt_ const char *salt_string,
        _Out_opt_ uint8_t *out_encrypted_buffer,
        _Inout_ size_t *out_encrypted_buffer_size
    );
}
