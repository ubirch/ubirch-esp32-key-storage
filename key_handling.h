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
 * Set backend public key.
 *
 * @param keybase64string The key in base64 string format, '\0' terminated
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

/*!
 * Read the backend pub Key value from memory
 *
 * @note:   After calling this function, the backend key is available in /p server_pub_key.
 *
 * @return  ESP_OK if keys were loaded sucessfully
 *          ESP_ERR... if any error occured
 */
esp_err_t load_backend_key(void);

#ifdef __cplusplus
}
#endif

#endif /* KEY_HANDLING_H */
