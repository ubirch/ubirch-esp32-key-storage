#include "unity.h"
#include <string.h>
//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include <esp_log.h>

#include <storage.h>
#include "ubirch_ed25519.h"
#include "id_handling.h"
#include "ubirch_protocol.h"

extern unsigned char UUID[16];
extern unsigned char ed25519_public_key[crypto_sign_PUBLICKEYBYTES];
extern unsigned char ed25519_secret_key[crypto_sign_SECRETKEYBYTES];

TEST_CASE("simple test", "[id handling]") {
	init_nvs();
    //TEST_ASSERT_EQUAL_STRING(ubirch_id_context_get(), "\0");
    TEST_ASSERT_NOT_EQUAL(ESP_OK, ubirch_id_context_load("invalid_id"));
}

TEST_CASE("create ids and select", "[id handling]") {
	init_nvs();
    // some dummy data for first id
    unsigned char uuid_1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char pub_key_1[] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    unsigned char sec_key_1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    unsigned char prev_sign_1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

    // some dummy data for second id
    unsigned char uuid_2[] = {
        0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char pub_key_2[] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    unsigned char sec_key_2[] = {
        0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    unsigned char prev_sign_2[] = {
        0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};


    // add first id
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_add("test_id_1"));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_uuid_set(uuid_1, sizeof(uuid_1)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_public_key_set(pub_key_1, sizeof(pub_key_1)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_secret_key_set(sec_key_1, sizeof(sec_key_1)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_previous_signature_set(prev_sign_1, sizeof(prev_sign_1)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_store());

    // add second id
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_add("test_id_2"));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_uuid_set(uuid_2, sizeof(uuid_2)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_public_key_set(pub_key_2, sizeof(pub_key_2)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_secret_key_set(sec_key_2, sizeof(sec_key_2)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_previous_signature_set(prev_sign_2, sizeof(prev_sign_2)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_store());

    unsigned char* prev_sign = NULL;
    size_t prev_sign_len = 0;

    // select first id
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_1"));
    // check if all values of first id are accessible
    TEST_ASSERT_EQUAL_UINT8_ARRAY(uuid_1, UUID, 16);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pub_key_1, ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sec_key_1, ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_previous_signature_get(&prev_sign, &prev_sign_len));
    TEST_ASSERT_EQUAL_INT(UBIRCH_PROTOCOL_SIGN_SIZE, prev_sign_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(prev_sign_1, prev_sign, prev_sign_len);

    // select second id
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_2"));
    // check if all values of second id are accessible
    TEST_ASSERT_EQUAL_UINT8_ARRAY(uuid_2, UUID, 16);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pub_key_2, ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sec_key_2, ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_previous_signature_get(&prev_sign, &prev_sign_len));
    TEST_ASSERT_EQUAL_INT(UBIRCH_PROTOCOL_SIGN_SIZE, prev_sign_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(prev_sign_2, prev_sign, prev_sign_len);
    // update some values
    uuid_2[1] = 42;
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_uuid_set(uuid_2, sizeof(uuid_2)));
    sec_key_2[2] = 123;
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_secret_key_set(sec_key_2, sizeof(sec_key_2)));
    // so we need to sync
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_store());

    // select first id again
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_1"));
    // check if all values of first id are accessible
    TEST_ASSERT_EQUAL_UINT8_ARRAY(uuid_1, UUID, 16);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pub_key_1, ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sec_key_1, ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_previous_signature_get(&prev_sign, &prev_sign_len));
    TEST_ASSERT_EQUAL_INT(UBIRCH_PROTOCOL_SIGN_SIZE, prev_sign_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(prev_sign_1, prev_sign, prev_sign_len);

    // select second id again
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_2"));
    // check if all values of second id are accessible
    TEST_ASSERT_EQUAL_UINT8_ARRAY(uuid_2, UUID, 16);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pub_key_2, ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sec_key_2, ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_previous_signature_get(&prev_sign, &prev_sign_len));
    TEST_ASSERT_EQUAL_INT(UBIRCH_PROTOCOL_SIGN_SIZE, prev_sign_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(prev_sign_2, prev_sign, prev_sign_len);
}

TEST_CASE("store certificate", "[id handling]") {
	// this test depends on the "create ids and select"-test
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_1"));
    char dummy_cert[] = {
        0x01, 0x02, 0x02, 0x03, 0x04, 0xf5, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0xfd, 0x0e, 0x0f,
        0x10, 0x17, 0x12, 0x13, 0x14, 0xf5, 0x16, 0x17,
        0x18, 0x19, 0x1f, 0x1b, 0x1c, 0xfd, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0xf5, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0xfd, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0xf5, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0xfd, 0x3e, 0x3f};
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_certificate_store(dummy_cert, sizeof(dummy_cert)));

    char* dummy_cert_restored = NULL;
    size_t dummy_cert_restored_len = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_certificate_load(&dummy_cert_restored, &dummy_cert_restored_len));
    TEST_ASSERT_EQUAL_INT(sizeof(dummy_cert), dummy_cert_restored_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(dummy_cert, dummy_cert_restored, sizeof(dummy_cert));
    ubirch_certificate_free();
}

TEST_CASE("next update", "[id handling]") {
	// this test depends on the "create ids and select"-test
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_1"));

    ubirch_id_state_set(UBIRCH_ID_STATE_KEYS_REGISTERED, true);

    const time_t timestamp = time(NULL);
    ubirch_next_key_update_set(timestamp);

    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_store());
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_1"));

    time_t timestamp2 = 0;
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_next_key_update_get(&timestamp2));

    TEST_ASSERT(ubirch_id_state_get(UBIRCH_ID_STATE_KEYS_REGISTERED));

    TEST_ASSERT_EQUAL_INT(timestamp, timestamp2);
}
