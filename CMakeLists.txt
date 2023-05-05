set(COMPONENT_SRCS
        key_handling.c
        token_handling.c
        id_handling.c
        )
set(COMPONENT_ADD_INCLUDEDIRS ".")

set(COMPONENT_REQUIRES
        ubirch-esp32-storage
        ubirch-protocol
        )

set(COMPONENT_PRIV_REQUIRES
        mbedtls
        )

register_component()
