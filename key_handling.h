/*!
 * @file    key_handling.h
 * @brief   key and signature helping functions
 *
 * @author Waldemar Gruenwald
 * @date   2018-10-10
 *
 * @copyright &copy; 2018 ubirch GmbH (https://ubirch.com)
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */



#ifndef KEY_HANDLING_H
#define KEY_HANDLING_H

#include <string.h>
#include "ubirch_ed25519.h"

#ifdef __cplusplus
extern "C" {
#endif

// length of base64 string is ceil(number_of_bytes / 3) * 4
// to get ceil for value / 3 (value >= 0) we use (value + 2) / 3
#define PUBLICKEY_BASE64_STRING_LENGTH (((crypto_sign_PUBLICKEYBYTES + 2) / 3) * 4)
#define BYTES_LENGTH_TO_BASE64_STRING_LENGTH(__len) (((__len + 2) / 3) * 4)

extern unsigned char server_pub_key[crypto_sign_PUBLICKEYBYTES];

/*!  
 * Create a new signature Key pair.
 *
 * After creating the key pair, it is packad into msgpack together with aditional
 * information, according to the structure `ubirch_key_info()`, from `ubirch_protocol_kex.h`,
 * which is part of the `ubirch-protocol` module.
 */
void create_keys(void);

/*!
 * Register the Keys in the backend.
 *
 * This function can only be executed, if a network connection is available.
 */
void register_keys(void);

/*!
 * Update the Keys in the backend.
 *
 * This function can only be executed, if a network connection is available.
 */
int update_keys(void);

/*!
 * Check the current key status.
 *
 * If no keys are present, create new keys. The key registration has to be executed separately.
 */
void check_key_status(void);

/*!
 * Set backend public key.
 *
 * @param key The key in base64 string format, '\0' terminated
 * @return ESP_OK if key was set successfully
 *         ESP_FAIL if any error occured
 */
esp_err_t set_backend_public_key(const char* keybase64string);

/*!
 * Set backend default public key given by Kconfig value CONFIG_UBIRCH_BACKEND_PUBLIC_KEY.
 *
 * @return ESP_OK if default key was set successfully
 *         ESP_FAIL if any error occured
 */
esp_err_t set_backend_default_public_key(void);

/*!
 * Get backend public key from flash in base64 format.
 *
 * @param buffer to write resulting string to
 * @param buffer_size size of provided buffer
 * @return ESP_OK if backened key was written to buffer successfully
 *         ESP_FAIL if any error occured
 */
esp_err_t get_backend_public_key(char* buffer, const size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* KEY_HANDLING_H */
