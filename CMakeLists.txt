set(COMPONENT_SRCS
        key_handling.c
        )
set(COMPONENT_ADD_INCLUDEDIRS ".")

set(COMPONENT_REQUIRES
        ubirch-esp32-networking
        ubirch-esp32-storage
        ubirch-protocol
        msgpack-c
        ubirch-esp32-api-http
        )

set(COMPONENT_PRIV_REQUIRES )

register_component()