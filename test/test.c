#include "unity.h"
#include <string.h>
//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include <esp_log.h>
#include <mbedtls/base64.h>
#include "key_handling.h"

// include compilation unit to be able to test static functions
#include "key_handling.c"

// dummy uuid
unsigned char UUID[16] = {0};


TEST_CASE("store and load default backend key", "[key handling]") {
    // store key from default configuration
    TEST_ASSERT_EQUAL_INT(ESP_OK, set_backend_default_public_key());
    TEST_ASSERT_EQUAL_INT(ESP_OK, load_backend_key());

    // load from base64 key from CONFIG_UBIRCH_BACKEND_PUBLIC_KEY
    unsigned char data[crypto_sign_PUBLICKEYBYTES] = {0};
    const char input[] = CONFIG_UBIRCH_BACKEND_PUBLIC_KEY;
    size_t len = 0;
    TEST_ASSERT_EQUAL_INT(0, mbedtls_base64_decode(data, crypto_sign_PUBLICKEYBYTES, &len,
                (const unsigned char*)input, strlen(input)));
    TEST_ASSERT_EQUAL_INT(crypto_sign_PUBLICKEYBYTES, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, server_pub_key, crypto_sign_PUBLICKEYBYTES);
}

TEST_CASE("store and load backend key", "[key handling]") {
    // store some key
    const char input[] = "42ABCDbAKFrwF3AJOBgwxGzsAl0B2GCF51pPAEHC5pA=";
    TEST_ASSERT_EQUAL_INT(ESP_OK, set_backend_public_key(input));
    TEST_ASSERT_EQUAL_INT(ESP_OK, load_backend_key());

    // load from base64 key from CONFIG_UBIRCH_BACKEND_PUBLIC_KEY
    unsigned char data[crypto_sign_PUBLICKEYBYTES] = {0};
    size_t len = 0;
    TEST_ASSERT_EQUAL_INT(0, mbedtls_base64_decode(data, crypto_sign_PUBLICKEYBYTES, &len,
                (const unsigned char*)input, strlen(input)));
    TEST_ASSERT_EQUAL_INT(crypto_sign_PUBLICKEYBYTES, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, server_pub_key, crypto_sign_PUBLICKEYBYTES);
}

TEST_CASE("reject broken keys", "[key handling]") {
    // try to store key of wrong length
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, set_backend_public_key("42ABCDbAKFrwF3AJOBgwxGzsAl0B2GCF51pPApA="));
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, set_backend_public_key("42ABCDbAKFrwF3AJOBgwxGzsAl0B2GCF51pPAE32425pA="));
    // try to store broken base64 key
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, set_backend_public_key("42ABCDbAKFrwF3AJOBgwxGzsAl0B2GCF51pPA!HC5pA="));
    // try to store base64 string that encodes key of wrong length
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, set_backend_public_key("42ABCDbAKFrwF3AJOBgwxGzsAl0B2GCF51pPAEHC5p=="));
}

TEST_CASE("get backend key in base64 format", "[key handling]") {
    // store some key
    const char input[] = "42ABCDbAKFrwF3AJOBgwxGzsAl0B2GCF51pPAEHC5pA=";
    printf("%s\n", input);
    TEST_ASSERT_EQUAL_INT(ESP_OK, set_backend_public_key(input));
    // load in base64 format, buffer needs space for terminating character
    char buffer[PUBLICKEY_BASE64_STRING_LENGTH + 1];
    TEST_ASSERT_EQUAL_INT(ESP_OK, get_backend_public_key((char*)buffer, sizeof(buffer)));
    TEST_ASSERT_EQUAL_STRING(input, buffer);
    printf("%s\n", buffer);
}

TEST_CASE("try to get backend key in base64 format into buffer that is too small", "[key handling]") {
    // store some key
    const char input[] = "42ABCDbAKFrwF3AJOBgwxGzsAl0B2GCF51pPAEHC5pA=";
    TEST_ASSERT_EQUAL_INT(ESP_OK, set_backend_public_key(input));
    // with buffer too small
    char buffer2[PUBLICKEY_BASE64_STRING_LENGTH];
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, get_backend_public_key((char*)buffer2, sizeof(buffer2)));
    printf("%s\n", buffer2);
}
