#include "unity.h"
#include <string.h>
//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include <esp_log.h>

#include <storage.h>

// load from compilation unit to be able to check static data
#include "token_handling.c"

TEST_CASE("store and load token", "[token handling]") {
    const char* token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"
        ".eyJpc3MiOiJodHRwczovL3Rva2VuLmRlbW8udWJpcmNoLmNvbSIsInN1Yi"
        "I6IjViM2VhMmMwLTA1NmQtNDY1My04Y2E3LWE1OTJmZjNjMDkzOSIsImF1Z"
        "CI6WyJodHRwczovL2FwaS5jb25zb2xlLmRlbW8udWJpcmNoLmNvbSIsImh0"
        "dHBzOi8vZGF0YS5kZW1vLnViaXJjaC5jb20iLCJodHRwczovL25pb21vbi5"
        "kZW1vLnViaXJjaC5jb20iLCJodHRwczovL3ZlcmlmeS5kZW1vLnViaXJjaC"
        "5jb20iXSwiZXhwIjoxNjM0NzM4MzI4LCJuYmYiOjE2MzIxNDYzMjksImlhd"
        "CI6MTYzMjE0NjM3OCwianRpIjoiMzExYzYyZmYtODlhNy00MDY1LTkwOTAt"
        "NmQyNTliM2NmNWIyIiwic2NwIjpbInRoaW5nOmNyZWF0ZSIsInRoaW5nOmd"
        "ldGluZm8iLCJ0aGluZzpzdG9yZWRhdGEiLCJ1cHA6YW5jaG9yIiwidXBwOn"
        "ZlcmlmeSJdLCJwdXIiOiJ0ZXN0LTMiLCJ0Z3AiOltdLCJ0aWQiOlsiMTA1M"
        "jFjNjctZGY2OC0xMjIzLTM0NDUtNTY2Nzc4ODk5YWFiIiwiMTA1MjFjNjct"
        "ZGY2OC0xMjIzLTM0NDUtNTY2Nzc4ODljY2NjIl0sIm9yZCI6W119"
        ".dwJMBotqJiXvBMmAuO5xzpRTv95Zo2T1zki78ITdQtCP31Gt-BAtrNJE-s"
        "xNADXOwemJqZaJT-kce8_I1dJycw";

    char* buffer;
    TEST_ASSERT_EQUAL(ESP_OK, ubirch_token_set(token));
    TEST_ASSERT_EQUAL(ESP_OK, ubirch_token_load());
    TEST_ASSERT_EQUAL(ESP_OK, ubirch_token_get((const char**)&buffer));
    TEST_ASSERT_EQUAL_STRING(token, buffer);
}
