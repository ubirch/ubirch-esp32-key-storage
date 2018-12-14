![ubirch logo](https://ubirch.de/wp-content/uploads/2018/10/cropped-uBirch_Logo.png)

# ubirch-esp32-key-storage

The ubirch-esp32-key-storage is a component, to handle the keys,
which are used to sign and verify messages.

## Prerequisits

The following components are required for the functionality, see also
[CMakeLists.txt](https://github.com/ubirch/ubirch-esp32-key-storage/blob/master/CMakeLists.txt)

- [ubirch-esp32-networking](https://github.com/ubirch/ubirch-esp32-networking)
- [ubirch-esp32-storage](https://github.com/ubirch/ubirch-esp32-storage)
- [ubirch-protocol](https://github.com/ubirch/ubirch-protocol.git)
- [ubirch-mbed-msgpack](https://github.com/ubirch/ubirch-mbed-msgpack)
- [ubirch-esp32-api-http](https://github.com/ubirch/ubirch-esp32-api-http)


## Functionality

The function `create_keys()` creates a new key pair and stores it in the
flash memory. Additionally it creates a [ubirch_key_info](https://github.com/ubirch/ubirch-protocol/blob/master/ubirch/ubirch_protocol_kex.h)
certificate with all relevant information about the keys. This structure
is then embedded in [msgpack](https://github.com/ubirch/ubirch-mbed-msgpack),
signed and stored into the flash memory.

The function `register_keys()` loads the key certificate from the flash
memory and sends it via [ubirch_send()](https://github.com/ubirch/ubirch-esp32-api-http/blob/master/ubirch_api.h)
to the ubirch backend.

The function `check_key_status()` checks for existing keys in the flash
memory and if no keys are present, creates new keys.