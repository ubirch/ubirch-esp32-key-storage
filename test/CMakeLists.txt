idf_component_register(
    SRC_DIRS "."
    INCLUDE_DIRS ".."
    REQUIRES
        unity
        ubirch-protocol
        ubirch-esp32-key-storage
        ubirch-esp32-api-http
    PRIV_REQUIRES
        mbedtls)
