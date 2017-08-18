#include <openssl/evp.h>
#include <boost/algorithm/hex.hpp>

#include "UserPreferences.h"
#include "Utils.h"

#pragma comment(lib, "libeay32")

namespace Encryption
{
    namespace
    {
        /// <summary>
        /// Decrypts ciphertext using the given key and initialization vector.
        /// </summary>
        /// <param name="ciphertext">Encrypted bytes to decrypt.</param>
        /// <param name="key">Key used for decryption.</param>
        /// <param name="initialization_vector">Initialization vector used for decryption.</param>
        /// <returns>Decrypted contents of ciphertext.</returns>
        std::vector<uint8_t> Decrypt(
            const std::vector<uint8_t> &ciphertext,
            const std::vector<uint8_t> &key,
            const std::vector<uint8_t> &initialization_vector)
        {
            auto out_plaintext = std::vector<uint8_t>(ciphertext.size());
            auto plaintext_length = 0;
            auto cipher = EVP_aes_256_cbc();
            auto ctx = EVP_CIPHER_CTX_new();

            EVP_CIPHER_CTX_init(ctx);

            if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, &key[0], &initialization_vector[0]))
            {
                EVP_CIPHER_CTX_free(ctx);
                throw std::exception("EVP_DecryptInit_ex - FAILED");
            }

            if (!EVP_DecryptUpdate(ctx, &out_plaintext[0], &plaintext_length, &ciphertext[0], static_cast<int>(ciphertext.size())))
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
        /// Encrypts plaintext into using the given key and initialization vector.
        /// </summary>
        /// <param name="plaintext">Plaintext to encrypt.</param>
        /// <param name="key">Key used for encryption.</param>
        /// <param name="initialization_vector">Initialization vector used for encryption.</param>
        /// <returns>Encrypted plaintext.</returns>
        std::vector<uint8_t> Encrypt(
            const std::vector<uint8_t> &plaintext,
            const std::vector<uint8_t> &key,
            const std::vector<uint8_t> &initialization_vector)
        {
            auto plaintext_length = 0;
            auto cipher = EVP_aes_256_cbc();
            auto ctx = EVP_CIPHER_CTX_new();

            auto num_blocks = plaintext.size() / cipher->block_size;
            if (plaintext.size() % cipher->block_size != 0) {
                ++num_blocks;
            }
            auto out_plaintext = std::vector<uint8_t>(cipher->block_size * num_blocks);
            memset(&out_plaintext[0], 0, out_plaintext.size());

            EVP_CIPHER_CTX_init(ctx);

            if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, &key[0], &initialization_vector[0]))
            {
                EVP_CIPHER_CTX_free(ctx);
                throw std::exception("EVP_EncryptInit_ex - FAILED");
            }

            if (!EVP_EncryptUpdate(ctx, &out_plaintext[0], &plaintext_length, &plaintext[0], static_cast<int>(plaintext.size())))
            {
                EVP_CIPHER_CTX_free(ctx);
                throw std::exception("EVP_EncryptUpdate - FAILED");
            }

            auto additional_length = 0;
            if (!EVP_EncryptFinal_ex(ctx, &out_plaintext[plaintext_length], &additional_length))
            {
                EVP_CIPHER_CTX_free(ctx);
                throw std::exception("EVP_EncryptFinal_ex - FAILED");
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

            for (size_t index = 0; index < kMangledDataSize; ++index)
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
        /// Encrypts or decrypts data
        /// </summary>
        /// <param name="data">Data to encrypt or decrypt</param>
        /// <param name="machine_guid">Machine GUID used to encrypt data</param>
        /// <param name="salt_string">Salt used to encrypt data</param>
        /// <param name="is_encrypting">Determines if data should be encrypted or decrypted</param>
        /// <returns>Encrypted or decrypted data</returns>
        std::vector<uint8_t> EncryptOrDecryptData(
            const std::vector<uint8_t>& data,
            const std::string& machine_guid,
            const std::string& salt_string,
            bool is_encrypting)
        {
            std::vector<uint8_t> salt_bytes;
            boost::algorithm::unhex(salt_string.begin(), salt_string.end(), std::back_inserter(salt_bytes));

            auto machine_guid_bytes = std::vector<uint8_t>(machine_guid.begin(), machine_guid.end());
            auto mangled_data = MangleData(machine_guid_bytes);

            std::vector<uint8_t> key;
            std::vector<uint8_t> initialization_vector;
            GetKeys(salt_bytes, mangled_data, key, initialization_vector);

            if (is_encrypting)
            {
                return Encrypt(data, key, initialization_vector);
            }
            else
            {
                return Decrypt(data, key, initialization_vector);
            }
        }
    }

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
