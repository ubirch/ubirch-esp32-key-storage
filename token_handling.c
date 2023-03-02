/*!
 * @file    token_handling.c
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


#include <stdio.h>
#include <string.h>
#include <esp_err.h>
#include <time.h>
#include <esp_log.h>
#include <storage.h>
#include <mbedtls/base64.h>

#include "token_handling.h"

//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

static const char *TAG = "TOKEN";

#define TOKEN_NVS_REGION "key_storage"
#define TOKEN_NVS_KEY "token"
#define TOKEN_STATE_NVS_KEY "state"

#define TOKEN_MAX_SIZE 2048
static struct {
    ubirch_token_state_t state;
    char data[TOKEN_MAX_SIZE];
} token = {
    .state = UBIRCH_TOKEN_STATE_VALID, // initially we assume the token is valid
    .data = { '\0' }
};

bool ubirch_token_state_get(ubirch_token_state_t state_bit_mask) {
    return (token.state & state_bit_mask);
}

void ubirch_token_state_set(const ubirch_token_state_t state_bit_mask, bool value) {
    if (value) {
        token.state |= state_bit_mask;
    } else {
        token.state &= ~state_bit_mask;
    }
}

esp_err_t ubirch_token_load(void) {
    ESP_LOGI(TAG, "load token from nvs");
    // 1. load token struct from nvs
	size_t len = TOKEN_MAX_SIZE - 1;
	char* token_ptr = token.data;
    esp_err_t err = kv_load(TOKEN_NVS_REGION, TOKEN_NVS_KEY, (void**)&token_ptr, &len);
    ESP_LOGI(TAG, "loaded %d bytes", len);
	token.data[len] = '\0';
    return err;
}

esp_err_t ubirch_token_set(const char* token_string) {
    ESP_LOGI(TAG, "set token");
    size_t string_length = strlen(token_string);
	if (string_length + 1 > TOKEN_MAX_SIZE) {
		return ESP_FAIL;
	}
    esp_err_t err = kv_store(TOKEN_NVS_REGION, TOKEN_NVS_KEY, (void*)token_string, string_length);

    return err;
}

esp_err_t ubirch_token_get(const char** buffer_ptr) {
    *buffer_ptr = token.data;
    return ESP_OK;
}
