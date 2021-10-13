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

//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

static const char *TAG = "KEYSTORE";

extern unsigned char UUID[16];

// define buffer for the key pair
unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES] = {};
unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES] = {};

// define buffer for server public key
unsigned char server_pub_key[crypto_sign_PUBLICKEYBYTES] = {};


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
                                         KEY_LIFETIME_IN_SECONDS);      // time until the key will be valid (now + 1 year)
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
    uint8_t dummy[1] = { 0 };
    size_t dummy_size = 1;
    if (kv_load("key_storage", "registered", (void **) &dummy, &dummy_size) == ESP_OK) {
        ESP_LOGI(TAG, "key already registered");
        return;
    }
    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();
    // try to load the certificate if it was generated and stored before
    if(kv_load("key_storage", "certificate", (void **) &sbuf->data, &sbuf->size) != ESP_OK) {
        ESP_LOGW(TAG, "creating new certificate");
        create_keys();
        if (kv_load("key_storage", "certificate", (void **) &sbuf->data, &sbuf->size) != ESP_OK) {
            ESP_LOGE(TAG, "failed to load certificate of new key");
            return;
        }
    } else {
        ESP_LOGI(TAG, "loaded certificate");
    }
    ESP_LOGI(TAG, "register identity");

    // send the data
    // TODO: verify response
    int http_status;
    if (ubirch_send(CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL, UUID, sbuf->data, sbuf->size, &http_status, NULL, NULL)
            == UBIRCH_SEND_OK) {
        if (http_status == 200) {
            ESP_LOGI(TAG, "successfull sent registration");
            if (kv_delete("key_storage", "certificate") != ESP_OK) {
                ESP_LOGE(TAG, "failed to delete registered certificate");
            }
            ESP_LOGI(TAG, "removed certificate from memory");
            if (kv_store("key_storage", "registered", dummy, dummy_size) != ESP_OK) {
                ESP_LOGE(TAG, "failed to store registered marker");
            }
        } else {
            ESP_LOGE(TAG, "unable to send registration");
        }
    } else {
        ESP_LOGE(TAG, "error while sending registration");
    }
    msgpack_sbuffer_free(sbuf);
}

int update_keys(void) {
    // get time information
    time_t now = time(NULL);

    // create new keys
    unsigned char new_ed25519_secret_key[crypto_sign_SECRETKEYBYTES] = {};
    unsigned char new_ed25519_public_key[crypto_sign_PUBLICKEYBYTES] = {};
    crypto_sign_keypair(new_ed25519_public_key, new_ed25519_secret_key);

    // convert keys into base64 format
    char old_pubKey[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_PUBLICKEYBYTES) + 1];
    unsigned int outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)old_pubKey, sizeof(old_pubKey),
                &outputlen, ed25519_public_key, crypto_sign_PUBLICKEYBYTES) != 0) {
        ESP_LOGW(TAG, "failed to convert old pub key to base64");
        return -1;
    }
    char new_pubKey[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_PUBLICKEYBYTES) + 1];
    outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)new_pubKey, sizeof(new_pubKey),
                &outputlen, new_ed25519_public_key, crypto_sign_PUBLICKEYBYTES) != 0) {
        ESP_LOGW(TAG, "failed to convert new pub key to base64");
        return -1;
    }

    // build update json string
    ubirch_update_key_info update_info = {
        .algorithm = UBIRCH_KEX_ALG_ECC_ED25519,
        .created = now,
        .hwDeviceId = UUID,
        .pubKey = new_pubKey,
        .prevPubKeyId = old_pubKey,
        .validNotAfter = now + KEY_LIFETIME_IN_SECONDS,
        .validNotBefore = now
    };

    // init with outer brace
    char json_string[610] = "{\"pubKeyInfo\":";
    char *inner_json_string = json_string + strlen(json_string);
    size_t inner_json_string_size = json_pack_key_update(&update_info, inner_json_string,
            sizeof(json_string) - strlen(json_string));
    ESP_LOGD(TAG, "inner json string size: %d", inner_json_string_size);
    ESP_LOGD(TAG, "inner json string: %s", inner_json_string);

    // sign json with old key
    unsigned char signature_old[crypto_sign_BYTES];
    if (ed25519_sign((unsigned char*)inner_json_string, inner_json_string_size, signature_old) != 0) {
        ESP_LOGW(TAG, "failed to sign with old key");
        return -1;
    }
    char signature_old_base64[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_BYTES) + 1];
    outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)signature_old_base64, sizeof(signature_old_base64),
                &outputlen, signature_old, crypto_sign_BYTES) != 0) {
        ESP_LOGW(TAG, "failed to convert signature to base64");
        return -1;
    }
    // sign json with new key
    unsigned char signature_new[crypto_sign_BYTES];
    if (ed25519_sign_key((unsigned char*)inner_json_string, inner_json_string_size, signature_new,
                new_ed25519_secret_key) != 0) {
        ESP_LOGW(TAG, "failed to sign with new key");
        return -1;
    }
    char signature_new_base64[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_BYTES) + 1];
    outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)signature_new_base64, sizeof(signature_new_base64),
                &outputlen, signature_new, crypto_sign_BYTES) != 0) {
        ESP_LOGW(TAG, "failed to convert signature to base64");
        return -1;
    }
    // add signatures to json string
    char *string_index = inner_json_string + inner_json_string_size;
    string_index += sprintf(string_index, ",\"signature\":\"%s\",\"prevSignature\":\"%s\"}",
            signature_new_base64, signature_old_base64);
    size_t json_string_size = string_index - json_string;
    ESP_LOGD(TAG, "update key json length: %d", json_string_size);
    ESP_LOGD(TAG, "update key json: %s", json_string);

    // send data
    int http_status;
    if (ubirch_send_json(CONFIG_UBIRCH_BACKEND_UPDATE_KEY_SERVER_URL, UUID,
                json_string, json_string_size, &http_status, NULL, NULL)
            == UBIRCH_SEND_OK) {
        if (http_status == 200) {
            ESP_LOGI(TAG, "successfull sent key update");
            memcpy(ed25519_secret_key, new_ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
            memcpy(ed25519_public_key, new_ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
            if (store_keys() != ESP_OK) {
                ESP_LOGE(TAG, "failed to store new keys");
                return -1;
            }
        } else {
            ESP_LOGW(TAG, "unable to send key update, http response is: %d", http_status);
            return -1;
        }
    } else {
        ESP_LOGW(TAG, "error while sending key update");
        return -1;
    }

    return 0;
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
