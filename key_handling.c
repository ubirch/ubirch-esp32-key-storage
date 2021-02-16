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
#include <ubirch_api.h>

#include "ubirch_ed25519.h"
#include "ubirch_protocol_kex.h"
#include "ubirch_protocol.h"

#include "key_handling.h"

static const char *TAG = "KEYSTORE";

extern unsigned char UUID[16];

// define buffer for the key pair
unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES] = {};
unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES] = {};

// define buffer for server public key
unsigned char server_pub_key[crypto_sign_PUBLICKEYBYTES] = {};

// length of base64 string is ceil(number_of_bytes / 3) * 4 (if number_of_bytes is > 0)
#define PUBLICKEY_BASE64_STRING_LENGTH ((1 + ((crypto_sign_PUBLICKEYBYTES - 1) / 3)) * 4)


/*!
 * Read the Key values from memory
 *
 * @note:   key buffer `ed25519_secret_key` and `ed25519_public_key` have to be allocated, before calling this function.
 *
 * @return  ESP_OK if keys were loaded sucessfully
 *          ESP_ERR... if any error occured
 */
static esp_err_t load_keys(void) {
    ESP_LOGI(TAG, "read keys");
    esp_err_t err;

    unsigned char *key = ed25519_secret_key;

    // read the secret key
    size_t size_sk = sizeof(ed25519_secret_key);
    err = kv_load("key_storage", "secret_key", (void **) &key, &size_sk);
    if (memory_error_check(err)) return err;

    // read the public key
    key = ed25519_public_key;
    size_t size_pk = sizeof(ed25519_public_key);
    err = kv_load("key_storage", "public_key", (void **) &key, &size_pk);
    if (memory_error_check(err)) return err;

    return err;
}


/*!
 * Write the key values to the memory
 *
 * @return  ESP_OK if keys were stored sucessfully
 *          ESP_ERR... if any error occured
 */
static esp_err_t store_keys(void) {
    ESP_LOGI(TAG, "write keys");
    esp_err_t err;
    // store the secret key
    err = kv_store("key_storage", "secret_key", ed25519_secret_key, sizeof(ed25519_secret_key));
    if (memory_error_check(err)) return err;
    //store the public key
    err = kv_store("key_storage", "public_key", ed25519_public_key, sizeof(ed25519_public_key));
    if (memory_error_check(err)) return err;

    return err;
}


/*!
 * Read the backend pub Key value from memory
 *
 * @note:   key buffer `server_pub_key` has to be allocated, before calling this function.
 *
 * @return  ESP_OK if keys were loaded sucessfully
 *          ESP_ERR... if any error occured
 */
static esp_err_t load_backend_key(void) {
    ESP_LOGI(TAG, "read server pub key");
    esp_err_t err;

    // read the public key
    unsigned char *key = server_pub_key;
    size_t size_pk = sizeof(server_pub_key);
    err = kv_load("key_storage", "server_key", (void **) &key, &size_pk);
    if (memory_error_check(err)) return err;

    return err;
}


/*!
 * Create a new signature Key pair
 */
void create_keys(void) {
    ESP_LOGI(TAG, "create keys");
    // create the key pair
    crypto_sign_keypair(ed25519_public_key, ed25519_secret_key);
    ESP_LOGD(TAG, "publicKey");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, (const char *) (ed25519_public_key), crypto_sign_PUBLICKEYBYTES, ESP_LOG_DEBUG);

    // create key registration info
    ubirch_key_info info = {};
    info.algorithm = (char *) (UBIRCH_KEX_ALG_ECC_ED25519);
    info.created = (unsigned int) time(NULL);                           // current time of the system
    memcpy(info.hwDeviceId, UUID, sizeof(UUID));                        // 16 Byte unique hardware device ID
    memcpy(info.pubKey, ed25519_public_key, sizeof(ed25519_public_key));// the public key
    info.validNotAfter = (unsigned int) (time(NULL) +
                                         31536000);        // time until the key will be valid (now + 1 year)
    info.validNotBefore = (unsigned int) time(NULL);                    // time from when the key will be valid (now)

    // create protocol context
    ubirch_protocol *upp = ubirch_protocol_new(UUID, ed25519_sign);

    // create the certificate for the key pair
    ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_REG, (const char *) &info, sizeof(info));

    // store the generated certificate
    esp_err_t err = kv_store("key_storage", "certificate", upp->data, upp->size);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "key certificate could not be stored in flash");
    }
    // store the keys
    if (store_keys() != ESP_OK) {
        ESP_LOGW(TAG, "generated keys could not be stored in flash");
    }
    // free allocated resources
    ubirch_protocol_free(upp);
}


void register_keys(void) {
    ESP_LOGI(TAG, "register identity");

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    // try to load the certificate if it was generated and stored before
    esp_err_t err = kv_load("key_storage", "certificate", (void **) &sbuf->data, &sbuf->size);
    if(err != ESP_OK) {
        ESP_LOGW(TAG, "creating new certificate");
        create_keys();
    } else {
        ESP_LOGI(TAG, "loaded certificate");
    }

    // send the data
    // TODO: verify response
    int http_status;
    if (ubirch_send(CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL, UUID, sbuf->data, sbuf->size, &http_status, NULL, NULL)
            == UBIRCH_SEND_OK) {
        if (http_status == 200) {
            ESP_LOGI(TAG, "successfull sent registration");
        } else {
            ESP_LOGE(TAG, "unable to send registration");
        }
    } else {
        ESP_LOGE(TAG, "error while sending registration");
    }
    msgpack_sbuffer_free(sbuf);
}


void check_key_status(void) {
    if (load_keys() != ESP_OK) {
        create_keys();
    }
    // only load default backend key if there is nothing in flash
    if (load_backend_key() != ESP_OK) {
        if (set_backend_default_public_key() != ESP_OK) {
            ESP_LOGE(TAG, "error setting backend pub key");
        }
    }
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
    ESP_LOG_BUFFER_HEXDUMP("key", server_pub_key, len, ESP_LOG_INFO);
    //store the public key
    esp_err_t err = kv_store("key_storage", "server_key", server_pub_key, crypto_sign_PUBLICKEYBYTES);
    if (memory_error_check(err)) return err;

    return err;
}
