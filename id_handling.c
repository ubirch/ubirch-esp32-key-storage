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

#define KVKEY_PERSISTENT_STATE ("state")
#define KVKEY_UUID ("uuid")
#define KVKEY_PASSWORD ("pw")
#define KVKEY_PUBLIC_KEY ("pub_key")
#define KVKEY_SECRET_KEY ("sec_key")
#define KVKEY_NEXT_KEY_UPDATE ("nxt_upd")
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
            uint8_t uuid_updated               :1;
            uint8_t password_updated           :1;
            uint8_t public_key_updated         :1;
            uint8_t secret_key_updated         :1;
            uint8_t next_key_update_updated    :1;
            uint8_t previous_signature_updated :1;
        };
        uint8_t raw;
    } memory_state;
} current_id_context = {
    .short_name = "\0",
    .state = 0x00,
    .memory_state.raw = 0x00
};

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
#define PASSWORD_LENGTH (36)
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
    current_id_context.memory_state.raw = 0x00;
    current_id_context.memory_state.valid = 1;
    return ESP_OK;
}
//esp_err_t ubirch_id_context_remove(const char* short_name);

const char* ubirch_id_context_get(void) {
    return current_id_context.short_name;
}

esp_err_t ubirch_id_context_load(const char* short_name) {
    // FIXME: open region only once and load all key-value pairs
    uint8_t* pmemory_state_addr = &current_id_context.state;
    esp_err_t ret = load_value(short_name, KVKEY_PERSISTENT_STATE,
            (void**)&pmemory_state_addr,
            sizeof(current_id_context.state));
    ESP_LOGD(TAG, "load: short_name = %s, state = %d", short_name, current_id_context.state);
    if (ret != ESP_OK) {
        current_id_context.memory_state.valid = 0;
        return ret;
    }
    unsigned char* addr = UUID;
    if ((ret = load_value(short_name, KVKEY_UUID,
                    (void**)&addr, sizeof(UUID))) != ESP_OK) {
        current_id_context.memory_state.valid = 0;
        return ret;
    }
    addr = (unsigned char*)current_password; // FIXME: uuaarrggh
    if (load_value(short_name, KVKEY_PASSWORD,
                    (void**)&addr, sizeof(current_password)) != ESP_OK) {
        current_id_context.state &= ~UBIRCH_ID_STATE_PASSWORD_SET;
    }
    addr = ed25519_public_key;
    if (load_value(short_name, KVKEY_PUBLIC_KEY,
                    (void**)&addr, sizeof(ed25519_public_key)) != ESP_OK) {
        current_id_context.state &= ~UBIRCH_ID_STATE_KEYS_CREATED;
    }
    addr = ed25519_secret_key;
    if (load_value(short_name, KVKEY_SECRET_KEY,
                    (void**)&addr, sizeof(ed25519_secret_key)) != ESP_OK) {
        current_id_context.state &= ~UBIRCH_ID_STATE_KEYS_CREATED;
    }
    time_t* next_key_update_addr = &next_key_update;
    if (load_value(short_name, KVKEY_NEXT_KEY_UPDATE,
                    (void**)&next_key_update_addr, sizeof(time_t)) != ESP_OK) {
        current_id_context.state &= ~UBIRCH_ID_STATE_KEYS_REGISTERED;
    }
    addr = previous_signature;
    if (load_value(short_name, KVKEY_PREVIOUS_SIGNATURE,
                    (void**)&addr, sizeof(previous_signature)) != ESP_OK) {
        current_id_context.state &= ~UBIRCH_ID_STATE_PREVIOUS_SIGNATURE_SET;
    }

    strncpy(current_id_context.short_name, short_name, ID_CONTEXT_SHORT_NAME_MAX_LEN);
    current_id_context.memory_state.raw = 0x00;
    current_id_context.memory_state.valid = 1;
    return ESP_OK;
}

esp_err_t ubirch_id_context_store(void) {
    ESP_LOGD(TAG, "store: short_name = %s, state = %d, memory_state = %d",
            current_id_context.short_name,
            current_id_context.state,
            current_id_context.memory_state.raw);
    esp_err_t ret = ESP_FAIL;
    if ((ret = store_value(current_id_context.short_name, KVKEY_PERSISTENT_STATE,
                    &current_id_context.state,
                    sizeof(current_id_context.state))) != ESP_OK) {
        return ret;
    }

    if ((current_id_context.memory_state.uuid_updated == 1) &&
            ((ret = store_value(current_id_context.short_name, KVKEY_UUID,
                                UUID, sizeof(UUID))) != ESP_OK)) {
        return ret;
    }
    current_id_context.memory_state.uuid_updated = 0;

    if ((current_id_context.memory_state.password_updated == 1) &&
            ((ret = store_value(current_id_context.short_name, KVKEY_PASSWORD,
                                current_password, strlen(current_password))) != ESP_OK)) {
        return ret;
    }
    current_id_context.memory_state.uuid_updated = 0;

    if ((current_id_context.memory_state.public_key_updated == 1) &&
            ((ret = store_value(current_id_context.short_name, KVKEY_PUBLIC_KEY,
                                ed25519_public_key, sizeof(ed25519_public_key))) != ESP_OK)) {
        return ret;
    }
    current_id_context.memory_state.public_key_updated = 0;

    if ((current_id_context.memory_state.secret_key_updated == 1) &&
            ((ret = store_value(current_id_context.short_name, KVKEY_SECRET_KEY,
                                ed25519_secret_key, sizeof(ed25519_secret_key))) != ESP_OK)) {
        return ret;
    }
    current_id_context.memory_state.secret_key_updated = 0;

    if ((current_id_context.memory_state.next_key_update_updated == 1) &&
            ((ret = store_value(current_id_context.short_name, KVKEY_NEXT_KEY_UPDATE,
                                &next_key_update, sizeof(time_t))) != ESP_OK)) {
        return ret;
    }
    current_id_context.memory_state.next_key_update_updated = 0;

    if ((current_id_context.memory_state.previous_signature_updated == 1) &&
            ((ret = store_value(current_id_context.short_name, KVKEY_PREVIOUS_SIGNATURE,
                                previous_signature, sizeof(previous_signature))) != ESP_OK)) {
        return ret;
    }
    current_id_context.memory_state.previous_signature_updated = 0;

    return ESP_OK;
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
}

esp_err_t ubirch_uuid_set(const unsigned char* uuid, size_t len) {
    if (len != UUID_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(UUID, uuid, len);
    current_id_context.memory_state.uuid_updated = 1;
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
    current_id_context.memory_state.password_updated = 1;
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
    current_id_context.memory_state.public_key_updated = 1;
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
    current_id_context.memory_state.secret_key_updated = 1;
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
    current_id_context.memory_state.next_key_update_updated = 1;
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
