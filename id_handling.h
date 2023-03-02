/*!
 * @file    id_handling.h
 * @brief   ID handling functions
 *
 * @author sven.herrmann@ubirch.com
 * @date   2021-10-10
 *
 * @copyright &copy; 2021 ubirch GmbH (https://ubirch.com)
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

#ifndef ID_HANDLING_H
#define ID_HANDLING_H

#include <esp_err.h>
#include <time.h>

#define UBIRCH_ID_CONTEXT_MAX_NR (3)

#ifdef __cplusplus
extern "C" {
#endif

#define UBIRCH_ID_STATE_KEYS_CREATED           (0b00000001)
#define UBIRCH_ID_STATE_PASSWORD_SET           (0b00000010)
#define UBIRCH_ID_STATE_KEYS_REGISTERED        (0b00000100)
#define UBIRCH_ID_STATE_PREVIOUS_SIGNATURE_SET (0b00001000)
typedef uint8_t ubirch_id_state_t;

/*!
 * Get a reference to short name of the current id context.
 *
 * @return reference to a zero-terminated string
 */
const char* ubirch_id_context_get(void);

/*!
 * Set the short name of the current id context.
 *
 * @param[in] short_name    new name for an id_context, not more than 15 characters
 * @return ESP_OK
 *         ESP_ERR_INVALID_ARG if short_name is too long
 */
esp_err_t ubirch_id_context_add(const char* short_name);

/*!
 * Remove context from memory if it exists.
 *
 * @param[in] short_name    new name for an id_context
 * @return ESP_OK
 *         ESP_ERR_INVALID_ARG if short_name is too long
 */
esp_err_t ubirch_id_context_remove(char* short_name);

/*!
 * Select an existing id context, i.e. the following variables
 * will be loaded and set:
 * - UUID (used with extern)
 * - ed25519_public_key (used with extern)
 * - ed25519_secret_key (used with extern)
 * - previous_signature
 *
 * @param[in] short_name    the short name of the existing context id to be selected
 * @return ESP_OK or an error code, if one of the variables could not be loaded
 */
esp_err_t ubirch_id_context_load(const char* short_name);

/*!
 * Store the data of the current id context into non volatile memory.
 *
 * @return ESP_OK or an error code if the storing failed
 */
esp_err_t ubirch_id_context_store(void);

/*!
 * Note: The following functions will depend on selected id context.
 * If you updated a value don't forget to call ubirch_id_context_store
 * to copy the data of the current id context to non volatile memory.
 */

/*!
 * Check if keys_registered flag is set.
 */
bool ubirch_id_state_get(ubirch_id_state_t state_bit_mask);

/*!
 * Check if keys_registered flag is set.
 */
void ubirch_id_state_set(const ubirch_id_state_t state_bit_mask, bool value);

/*!
 * Set the uuid of the current id context.
 *
 * @param[in] uuid      the uuid to be set
 * @param[in] len       size of the new uuid
 * @return ESP_OK or an error code if setting failed
 */
esp_err_t ubirch_uuid_set(const unsigned char* uuid, size_t len);

/*!
 * Get the pointer referencing the current uuid.
 *
 * @param[in,out] uuid      reference to a pointer
 * @param[in,out] len       size of data which is accessible at the pointer
 * @return ESP_OK or ESP_FAIL if current id is not properly loaded
 */
esp_err_t ubirch_uuid_get(unsigned char** uuid, size_t* len);

/*!
 * Set the password of the current id context.
 *
 * @param[in] password  the password to be set
 * @param[in] len       size of the new password
 * @return ESP_OK or an error code if setting failed
 */
esp_err_t ubirch_password_set(const char* password, size_t len);

/*!
 * Get the pointer referencing the current password.
 *
 * @param[in,out] password  reference to a pointer
 * @param[in,out] len       size of data which is accessible at the pointer
 * @return ESP_OK or ESP_FAIL if current id is not properly loaded
 */
esp_err_t ubirch_password_get(char** password, size_t* len);

/*!
 * Set the public key of the current id context.
 *
 * @param[in] public_key    the public key to be set
 * @param[in] len           size of the new public key
 * @return ESP_OK or an error code if setting failed
 */
esp_err_t ubirch_public_key_set(const unsigned char* public_key, size_t len);

/*!
 * Get the pointer referencing the public key.
 *
 * @param[in,out] public_key    reference to a pointer
 * @param[in,out] len           size of data which is accessible at the pointer
 * @return ESP_OK or ESP_FAIL if current id is not properly loaded
 */
esp_err_t ubirch_public_key_get(unsigned char** public_key, size_t* len);

/*!
 * Set the secret key of the current id context.
 *
 * @param[in] secret_key    the secret key to be set
 * @param[in] len           size of the new secret key
 * @return ESP_OK or an error code if setting failed
 */
esp_err_t ubirch_secret_key_set(const unsigned char* secret_key, size_t len);

/*!
 * Get the pointer referencing the secret key.
 *
 * @param[in,out] secret_key    reference to a pointer
 * @param[in,out] len           size of data which is accessible at the pointer
 * @return ESP_OK or ESP_FAIL if current id is not properly loaded
 */
esp_err_t ubirch_secret_key_get(unsigned char** secret_key, size_t* len);

/*!
 * Set the next key update of the current id context.
 *
 * @param[in] next_update       unix timestamp for next key update
 */
void ubirch_next_key_update_set(const time_t next_update);

/*!
 * Get the next key update of the current id context.
 *
 * @param[in,out] next_update   unix timestamp for next key update
 * @return ESP_OK or ESP_FAIL if current id is not properly loaded
 */
esp_err_t ubirch_next_key_update_get(time_t* next_update);

/*!
 * Set the previous signature of the current id context.
 *
 * @param[in] signature     the previous signature to be set
 * @param[in] len           size of the new secret key
 * @return ESP_OK or an error code if setting failed
 */
esp_err_t ubirch_previous_signature_set(const unsigned char* signature, size_t len);

/*!
 * Get the pointer referencing the previous signature.
 *
 * @param[in,out] signature     reference to a pointer
 * @param[in,out] len           size of data which is accessible at the pointer
 * @return ESP_OK or ESP_FAIL if current id is not properly loaded
 */
esp_err_t ubirch_previous_signature_get(unsigned char** signature, size_t* len);

/*!
 * Store certificate to current id.
 *
 * @param[in] certificate   certificate data to store
 * @param[in] len           length of data
 * @return ESP_OK or an error code if storing failed
 */
esp_err_t ubirch_certificate_store(char* certificate, size_t len);

/*!
 * Load certificate from non volatile memory into heap and return pointer.
 * Note: Don't forget to free the data via ubirch_certificate_free!
 *
 * @param[in,out] certificate   pointer to store reference to heap with certificate data
 * @param[in,out] len           length of certificate data
 * @return ESP_OK or an error code if loading failed
 */
esp_err_t ubirch_certificate_load(char** certificate, size_t* len);

/*!
 * Remove certificate from current id in non volatile memory.
 *
 * @return ESP_OK or an error code if deletion failed
 */
esp_err_t ubirch_certificate_remove(void);

/*!
 * Free pointer to certificate data.
 */
void ubirch_certificate_free(void);


#ifdef __cplusplus
}
#endif

#endif // ID_HANDLING_H
