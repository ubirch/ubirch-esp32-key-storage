![ubirch logo](https://ubirch.de/wp-content/uploads/2018/10/cropped-uBirch_Logo.png)

# ubirch-esp32-key-storage

The ubirch-esp32-key-storage is a component, to handle everything related to
ubirch backend public keys and to one or multiple ubirch device IDs,
i.e. their state, the UUIDs, passwords, public and secret keys,
the previous signatures and the "certificates" (a signed version of the public key
plus some meta-data).

The functions in [`id_handling.h`](https://github.com/ubirch/ubirch-esp32-key-storage/blob/master/id_handling.h)
are used to load and store data which is ID specific and the functions in
[key_handling.h](https://github.com/ubirch/ubirch-esp32-key-storage/blob/master/key_handling.h)
are used to load and store backend specific data.
For an usage example see [ubirch-esp32-api-http](https://github.com/ubirch/ubirch-esp32-api-http).

## Prerequisits

The following components are required for the functionality, see also
[CMakeLists.txt](https://github.com/ubirch/ubirch-esp32-key-storage/blob/master/CMakeLists.txt)

- [ubirch-esp32-storage](https://github.com/ubirch/ubirch-esp32-storage)
- [ubirch-protocol](https://github.com/ubirch/ubirch-protocol.git)
