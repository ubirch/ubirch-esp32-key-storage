/*!
 * @file    key handling.c
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


#include <stdio.h>
#include <string.h>
#include <esp_err.h>
#include <time.h>
#include <esp_log.h>
#include <storage.h>
#include <mbedtls/base64.h>

#include "key_handling.h"

//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

static const char *TAG = "KEYSTORE";

// define buffer for server public key
unsigned char server_pub_key[crypto_sign_PUBLICKEYBYTES] = {};

typedef struct key_status_t {
    unsigned int keys_registered: 1;
    time_t next_update;
} key_status_t;


/*!
 * Read the backend pub Key value from memory
 *
 * @note:   key buffer `server_pub_key` has to be allocated, before calling this function.
 *
 * @return  ESP_OK if keys were loaded sucessfully
 *          ESP_ERR... if any error occured
 */
esp_err_t load_backend_key(void) {
    ESP_LOGI(TAG, "read server pub key");
    esp_err_t err;

    // read the public key
    unsigned char *key = server_pub_key;
    size_t size_pk = sizeof(server_pub_key);
    err = kv_load("key_storage", "server_key", (void **) &key, &size_pk);
    if (memory_error_check(err)) return err;

    return err;
}


esp_err_t set_backend_default_public_key(void) {
    return set_backend_public_key(CONFIG_UBIRCH_BACKEND_PUBLIC_KEY);
}


esp_err_t set_backend_public_key(const char* keybase64string) {
    size_t len = strlen(keybase64string);
    if (len != PUBLICKEY_BASE64_STRING_LENGTH) {
        ESP_LOGE(TAG, "unexpected base64 string length");
        return ESP_FAIL;
    }
    size_t outputlen = 0;
    if (mbedtls_base64_decode(server_pub_key, crypto_sign_PUBLICKEYBYTES, &outputlen,
            (const unsigned char*)keybase64string, len) != 0) {
        ESP_LOGE(TAG, "decoding base64 failed");
        return ESP_FAIL;
    }
    if (outputlen != crypto_sign_PUBLICKEYBYTES) {
        ESP_LOGE(TAG, "decoding base64 returned unexpected key length");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "setting backend public key");
    ESP_LOG_BUFFER_HEXDUMP("key", server_pub_key, crypto_sign_PUBLICKEYBYTES, ESP_LOG_INFO);
    //store the public key
    esp_err_t err = kv_store("key_storage", "server_key", server_pub_key, crypto_sign_PUBLICKEYBYTES);
    if (memory_error_check(err)) return err;

    return err;
}


esp_err_t get_backend_public_key(char* buffer, const size_t buffer_size) {
    if (load_backend_key() != ESP_OK) {
        return ESP_FAIL;
    }
    unsigned int outputlen = 0;
    switch (mbedtls_base64_encode((unsigned char*)buffer, buffer_size, &outputlen, server_pub_key, crypto_sign_PUBLICKEYBYTES)) {
        case 0:
            break;
        case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
            ESP_LOGE(TAG, "buffer size too small");
            return ESP_FAIL;
        default:
            ESP_LOGE(TAG, "error encoding to base64");
            return ESP_FAIL;
    }
    return ESP_OK;
}
