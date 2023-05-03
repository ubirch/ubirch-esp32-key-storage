/*!
 * @file    id_handling.c
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


#include <esp_log.h>

#include <storage.h>
#include "id_handling.h"
#include "ubirch_ed25519.h"

#include "ubirch_protocol.h"

//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#define ID_CONTEXT_SHORT_NAME_MAX_LEN (15)
#define UUID_LEN (16)
#define PASSWORD_LENGTH (36)

#define KVKEY_ID_BLOB ("blob")
#define KVKEY_CERTIFICATE ("cert")
#define KVKEY_PREVIOUS_SIGNATURE ("pre_sign")

static const char *TAG = "ID_HANDLING";

/*
 * current context, initially empty
 */
static struct {
    char short_name[ID_CONTEXT_SHORT_NAME_MAX_LEN + 1];
    ubirch_id_state_t state;
    union {
        struct {
            uint8_t valid                      :1;
            uint8_t id_blob_updated            :1;
            uint8_t previous_signature_updated :1;
        };
        uint8_t raw;
    } memory_state;
} current_id_context = {
    .short_name = "\0",
    .state = 0x00,
    .memory_state.raw = 0x00
};

#define ID_BLOB_LENGTH (sizeof(current_id_context.state) + UUID_LEN + PASSWORD_LENGTH + 1 \
        + crypto_sign_SECRETKEYBYTES + sizeof(time_t))

/*
 * global variables, used with extern
 * aka current values
 */
unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES];
unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES];
unsigned char UUID[UUID_LEN];

/*
 *
 */
static char current_password[PASSWORD_LENGTH + 1] = { '\0' };
static char* certificate = NULL;
static unsigned char previous_signature[UBIRCH_PROTOCOL_SIGN_SIZE];
static time_t next_key_update = 0;

/*!
 * Load value from non volatile memory.
 *
 * @param[in] region
 * @param[in] short_name -
 * @param[out] dest       -
 * @param[] len        -
 * @return ESP_OK or error code in case of failure
 */
static esp_err_t load_value(const char* short_name, char* key, void** dest, const size_t len) {
    size_t actual_len = len;
    esp_err_t ret = kv_load((char*)short_name, key, dest, &actual_len);
    if (memory_error_check(ret)) {
        ESP_LOGW(TAG, "cannot load %s for %s", key, short_name);
    }
    return ret;
}

static esp_err_t store_value(char* short_name, char* key, void* val, const size_t len) {
    esp_err_t ret = kv_store(short_name, key, val, len);
    if (memory_error_check(ret)) {
        ESP_LOGW(TAG, "cannot store %s for %s", key, short_name);
    }
    return ret;
}

esp_err_t ubirch_id_context_add(const char* short_name) {
    if (strlen(short_name) > ID_CONTEXT_SHORT_NAME_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    strncpy(current_id_context.short_name, short_name, ID_CONTEXT_SHORT_NAME_MAX_LEN);
    current_id_context.state = 0x00;
    current_id_context.memory_state.raw = 0x00;
    current_id_context.memory_state.valid = 1;
    return ESP_OK;
}

esp_err_t ubirch_id_context_delete(char* short_name) {
    if (short_name == NULL) {
        short_name = current_id_context.short_name;
    }
    if (strlen(short_name) > ID_CONTEXT_SHORT_NAME_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t ret = ESP_OK;
    if (kv_delete((char*)short_name, KVKEY_ID_BLOB) != ESP_OK) {
        ESP_LOGE(TAG, "failed to delete id-blob from kv-storage");
        ret = ESP_FAIL;
    }
    if (kv_delete((char*)short_name, KVKEY_CERTIFICATE) != ESP_OK) {
        ESP_LOGE(TAG, "failed to delete certificate from kv-storage");
        ret = ESP_FAIL;
    }
    if (kv_delete((char*)short_name, KVKEY_PREVIOUS_SIGNATURE) != ESP_OK) {
        ESP_LOGE(TAG, "failed to delete previous signature from kv-storage");
        ret = ESP_FAIL;
    }

    if (strcmp(short_name, current_id_context.short_name) == 0) {
        current_id_context.memory_state.raw = 0x00;
        current_id_context.memory_state.valid = 0;
        current_id_context.memory_state.id_blob_updated = 0;
        current_id_context.memory_state.previous_signature_updated = 0;
    }

    return ret;
}

const char* ubirch_id_context_get(void) {
    return current_id_context.short_name;
}

esp_err_t ubirch_id_context_load(const char* short_name) {
    ESP_LOGD(TAG, "load: short_name = %s, state = %d", short_name, current_id_context.state);
    // load id blob
    unsigned char id_blob_buffer[ID_BLOB_LENGTH];
    unsigned char* addr = id_blob_buffer;
    esp_err_t ret = load_value(short_name, KVKEY_ID_BLOB, (void**)&addr, ID_BLOB_LENGTH);
    if (ret != ESP_OK) {
        return ret;
    }

    unsigned char* id_blob_buffer_ptr = id_blob_buffer;
    // copy state from buffer
    memcpy(&current_id_context.state, id_blob_buffer_ptr, sizeof(current_id_context.state));
    id_blob_buffer_ptr = id_blob_buffer_ptr + sizeof(current_id_context.state);

    // copy UUID from buffer
    memcpy(UUID, id_blob_buffer_ptr, UUID_LEN);
    id_blob_buffer_ptr = id_blob_buffer_ptr + UUID_LEN;

    // copy password from buffer
    memcpy(current_password, id_blob_buffer_ptr, PASSWORD_LENGTH + 1);
    id_blob_buffer_ptr = id_blob_buffer_ptr + PASSWORD_LENGTH + 1;

    // copy keypair from buffer
    memcpy(ed25519_secret_key, id_blob_buffer_ptr, crypto_sign_SECRETKEYBYTES);
    id_blob_buffer_ptr = id_blob_buffer_ptr + (crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES);
    memcpy(ed25519_public_key, id_blob_buffer_ptr, crypto_sign_PUBLICKEYBYTES);
    id_blob_buffer_ptr = id_blob_buffer_ptr + crypto_sign_PUBLICKEYBYTES;

    // copy next_key_update from buffer
    memcpy(&next_key_update, id_blob_buffer_ptr, sizeof(time_t));

    // load previous signature
    addr = previous_signature;
    if (load_value(short_name, KVKEY_PREVIOUS_SIGNATURE,
                    (void**)&addr, UBIRCH_PROTOCOL_SIGN_SIZE) != ESP_OK) {
        current_id_context.state &= ~UBIRCH_ID_STATE_PREVIOUS_SIGNATURE_SET;
    }

    strncpy(current_id_context.short_name, short_name, ID_CONTEXT_SHORT_NAME_MAX_LEN);
    current_id_context.memory_state.valid = 1;
    current_id_context.memory_state.id_blob_updated = 0;
    current_id_context.memory_state.previous_signature_updated = 0;

    return ESP_OK;
}

esp_err_t ubirch_id_context_store(void) {
    ESP_LOGD(TAG, "store: short_name = %s, state = %d, memory_state = %d",
            current_id_context.short_name,
            current_id_context.state,
            current_id_context.memory_state.raw);
    esp_err_t ret = ESP_OK;

    if (current_id_context.memory_state.id_blob_updated == 1) {
        // create ID_BLOB from data
        unsigned char id_blob_buffer[ID_BLOB_LENGTH];
        unsigned char* id_blob_buffer_ptr = id_blob_buffer;

        // copy state to
        memcpy(id_blob_buffer_ptr, &current_id_context.state, sizeof(current_id_context.state));
        id_blob_buffer_ptr = id_blob_buffer_ptr + sizeof(current_id_context.state);

        // copy UUID to buffer
        memcpy(id_blob_buffer_ptr, UUID, UUID_LEN);
        id_blob_buffer_ptr = id_blob_buffer_ptr + UUID_LEN;

        // copy password to buffer
        memcpy(id_blob_buffer_ptr, current_password, PASSWORD_LENGTH + 1);
        id_blob_buffer_ptr = id_blob_buffer_ptr + PASSWORD_LENGTH + 1;

        // copy keypair to buffer
        memcpy(id_blob_buffer_ptr, ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
        id_blob_buffer_ptr = id_blob_buffer_ptr + crypto_sign_SECRETKEYBYTES;

        // copy next_key_update to buffer
        memcpy(id_blob_buffer_ptr, &next_key_update, sizeof(time_t));

        // store id blob
        if ((ret = store_value(current_id_context.short_name, KVKEY_ID_BLOB,
                        id_blob_buffer, ID_BLOB_LENGTH)) != ESP_OK) {
            return ret;
        }
        current_id_context.memory_state.id_blob_updated = 0;
    }

    if ((current_id_context.memory_state.previous_signature_updated == 1) &&
            ((ret = store_value(current_id_context.short_name, KVKEY_PREVIOUS_SIGNATURE,
                                previous_signature, sizeof(previous_signature))) != ESP_OK)) {
        return ret;
    }
    current_id_context.memory_state.previous_signature_updated = 0;

    return ret;
}

bool ubirch_id_state_get(ubirch_id_state_t state_bit_mask) {
    return (current_id_context.state & state_bit_mask);
}

void ubirch_id_state_set(const ubirch_id_state_t state_bit_mask, bool value) {
    if (value) {
        current_id_context.state |= state_bit_mask;
    } else {
        current_id_context.state &= ~state_bit_mask;
    }
    current_id_context.memory_state.id_blob_updated = 1;
}

esp_err_t ubirch_uuid_set(const unsigned char* uuid, size_t len) {
    if (len != UUID_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(UUID, uuid, len);
    current_id_context.memory_state.id_blob_updated = 1;
    return ESP_OK;
}

esp_err_t ubirch_uuid_get(unsigned char** uuid, size_t* len) {
    if (current_id_context.memory_state.valid == 0) {
        return ESP_FAIL;
    }
    *uuid = UUID;
    *len = UUID_LEN;
    return ESP_OK;
}

esp_err_t ubirch_password_set(const char* password, size_t len) {
    if (len != PASSWORD_LENGTH) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(current_password, password, len);
    current_password[PASSWORD_LENGTH + 1] = 0x00;
    current_id_context.memory_state.id_blob_updated = 1;
    return ESP_OK;
}

esp_err_t ubirch_password_get(char** password, size_t* len) {
    if (current_id_context.memory_state.valid == 0) {
        return ESP_FAIL;
    }
    *password = current_password;
    *len = UUID_LEN;
    return ESP_OK;
}

esp_err_t ubirch_public_key_set(const unsigned char* public_key, size_t len) {
    if (len != crypto_sign_PUBLICKEYBYTES) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(ed25519_public_key, public_key, len);
    current_id_context.memory_state.id_blob_updated = 1;
    return ESP_OK;
}

esp_err_t ubirch_public_key_get(unsigned char** public_key, size_t* len) {
    if (current_id_context.memory_state.valid == 0) {
        return ESP_FAIL;
    }
    *public_key = ed25519_public_key;
    *len = crypto_sign_PUBLICKEYBYTES;
    return ESP_OK;
}

esp_err_t ubirch_secret_key_set(const unsigned char* secret_key, size_t len) {
    if (len != crypto_sign_SECRETKEYBYTES) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(ed25519_secret_key, secret_key, len);
    current_id_context.memory_state.id_blob_updated = 1;
    return ESP_OK;
}

esp_err_t ubirch_secret_key_get(unsigned char** secret_key, size_t* len) {
    if (current_id_context.memory_state.valid == 0) {
        return ESP_FAIL;
    }
    *secret_key = ed25519_secret_key;
    *len = crypto_sign_SECRETKEYBYTES;
    return ESP_OK;
}

void ubirch_next_key_update_set(const time_t next_update) {
    next_key_update = next_update;
    current_id_context.memory_state.id_blob_updated = 1;
}

esp_err_t ubirch_next_key_update_get(time_t* next_update) {
    if (current_id_context.memory_state.valid == 0) {
        return ESP_FAIL;
    }
    *next_update = next_key_update;
    return ESP_OK;
}

esp_err_t ubirch_previous_signature_set(const unsigned char* signature, size_t len) {
    if (len != UBIRCH_PROTOCOL_SIGN_SIZE) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(previous_signature, signature, len);
    current_id_context.memory_state.previous_signature_updated = 1;
    current_id_context.state |= UBIRCH_ID_STATE_PREVIOUS_SIGNATURE_SET;
    return ESP_OK;
}

esp_err_t ubirch_previous_signature_get(unsigned char** signature, size_t* len) {
    if (current_id_context.memory_state.valid == 0) {
        return ESP_FAIL;
    }
    *signature = previous_signature;
    *len = UBIRCH_PROTOCOL_SIGN_SIZE;
    return ESP_OK;
}

esp_err_t ubirch_certificate_store(char* cert, size_t len) {
    return kv_store(current_id_context.short_name, KVKEY_CERTIFICATE, cert, len);
}

esp_err_t ubirch_certificate_load(char** cert, size_t* len) {
    *len = 0;
    esp_err_t ret = kv_load(current_id_context.short_name, KVKEY_CERTIFICATE, (void**)&certificate, len);
    if (ret == ESP_OK) {
        *cert = certificate;
    }
    return ret;
}

esp_err_t ubirch_certificate_remove(void) {
    return kv_delete(current_id_context.short_name, KVKEY_CERTIFICATE);
}

void ubirch_certificate_free(void) {
    free(certificate);
}
