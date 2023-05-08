/*!
 * @file    token_handling.h
 * @brief   token helping functions
 *
 * @author Sven Herrmann
 * @date   2023-02-09
 *
 * @copyright &copy; 2023 ubirch GmbH (https://ubirch.com)
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

#ifndef TOKEN_HANDLING_H
#define TOKEN_HANDLING_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UBIRCH_TOKEN_STATE_VALID (0b00000001)
#define UBIRCH_TOKEN_STATE_USED  (0b00000010)
typedef uint8_t ubirch_token_state_t;

/*!
 * Check token state.
 *
 * @param state_bit_mask The bit mask to check against
 * @return true if the state of /p state_bit_mask coresponds with state of token
 */
bool ubirch_token_state_get(ubirch_token_state_t state_bit_mask);

/*!
 * Set token. Also set it in NVS memory.
 *
 * @param key The key in base64 string format, '\0' terminated
 * @return ESP_OK if key was set successfully
 *         ESP_FAIL if any error occured
 */
esp_err_t ubirch_token_set(const char* token_string);

/*!
 * Get token that allows for generating devices in the backend.
 *
 * @param buffer to write resulting string to
 * @param buffer_size size of provided buffer
 * @return ESP_OK if token was written to buffer successfully
 */
esp_err_t ubirch_token_get(const char** buffer);

/*!
 * Load token from NVS memory.
 *
 * @return ESP_OK if token was loaded successfully
 *         ESP_FAIL if any error occured
 */
esp_err_t ubirch_token_load(void);

#ifdef __cplusplus
}
#endif

#endif /* TOKEN_HANDLING_H */
