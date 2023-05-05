![ubirch logo](https://ubirch.de/wp-content/uploads/2018/10/cropped-uBirch_Logo.png)

# ubirch-esp32-key-storage

The ubirch-esp32-key-storage is a component, to handle everything related to
ubirch backend public keys, ubirch device IDs,
i.e. their state, the UUIDs, passwords, public and secret keys,
the previous signatures and the "certificates" (a signed version of the public key
plus some meta-data). It is also used to store and handle JWT tokens for automatic device registration.

The functions in [`id_handling.h`](./id_handling.h)
are used to load and store data which is ID specific and the functions in
[key_handling.h](./key_handling.h) are used to load and store backend specific data.
The functions in [token_handling.h](./token_handling.h) are used to load and store the JWT token.

For an example usage see [ubirch-esp32-api-http](https://github.com/ubirch/ubirch-esp32-api-http).

## Prerequisits

The following components are required for the functionality, see also
[CMakeLists.txt](./CMakeLists.txt)

- [ubirch-esp32-storage](https://github.com/ubirch/ubirch-esp32-storage)
- [ubirch-protocol](https://github.com/ubirch/ubirch-protocol.git)

# ubirch ID handling and registration

In order to simplify the management of ubirch identities and the correspondet keys and configurations, 
the built-in partition `nvs` of the flash storage is used ([Built-in Partition Tables](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html#built-in-partition-tables)))
where this data is stored, without the need of modifying the codebase.
The application is then able to load and store the values in the `nvs` via specific functions from [ubirch-esp32-storage](https://github.com/ubirch/ubirch-esp32-storage)

Before storing the data, it has to be prepared. The first step is to generate a csv file from the data.
Therefore the python script [create_nvs_memory.py](./create_nvs_memory.py) is used.

## usage of `create_nvs_memory.py`

Create the nvs-flash-partition description csv-file (for more details compare
[the esp-idf documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_partition_gen.html))

The python script has some optional input arguments, which will be explained by this examplary usage:
```[bash]
$ python create_nvs_memory.py --json device_config.json --stage demo --token <insert your token string here> --out out.csv 
```
- `--json device_config.json` is necessary for identity configurations to be stored. 
If no `--out` argument is specified, the output file will be `device_config.csv`
- `--stage demo` specifies the stage of the ubirch backend, which is needed to provide the public key. 
If this argument is not used, the default value `prod` will be used.
- `--token <insert your token string here>` specifies the JWT token.
- `--out out.csv` specifies the output file.

There are multiple possibilities to use the script, which depend the application.

### Configuration of single ubirch ID with pre-generated uuid

Use e.g. `$ uuidgen` to generate a new uuid and [register your device with this uuid in the Backend](#register-your-device-in-the-backend).
Create a json-file (e.g. `my_device_config.json`) including the following json object with the information from your registered device:
```json
{
  "short_name": "default_id",
  "uuid": "<uuid>",
  "password": "<password>"
}
```
Now run the python script:
```bash
$ python create_nvs_memory.py --json my_device_config.json 
```
> Note that the `short_name` i.e. `default_id` will be referenced in the application to access the identity context 
(e.g. in [example-esp32](https://github.com/ubirch/example-esp32/blob/master/main/main.c#L70)). 

### Configuration of multiple identities

To use multiple ubirch IDs on your device it is necessary to activate the option `UBIRCH_MULTIPLE_IDS` in the menuconfig of your application
(e.g. in [example-esp32 Kconfig](https://github.com/ubirch/example-esp32/blob/master/main/Kconfig.projbuild#L27-L28)) via `$ make menuconfig`,
navigate to `Ubirch Application` and set `Enable multiple ids`. 

Follow the same steps as in [the previous section](#configuration-of-single-ubirch-id-with-pre-generated-uuid)
but register multiple devices and put a list of them in the json-file:
```json
[
  {
    "short_name": "foo",
    "uuid": "<uuid-1>",
    "password": "<password-1>"
  },
  {
    "short_name": "bar",
    "uuid": "<uuid-2>",
    "password": "<password-2>"
  }
]
```
> Note that the `short_name`s are used to load the IDs from memory, see [here](https://github.com/ubirch/example-esp32/blob/master/main/main.c#L96).

The number of IDs that can be used at once depend on the partition size.
Each ID needs about 230 byte of memory (including nvs overhead), the backend key
needs 64 byte (including nvs overhead) and the wifi credentials need space depending on SSID and password length.

### Configuration of JWT Token for automatic device registration

For the automatic registration of new sensors to the ubirch backend, it is necessary to use a JWT token. For information about how to generate a JWT token, please refer to [Use JWT Token for ...](files/Use%20JWT%20for%20creating%20and%20managing%20things-v3-20230405.pdf). Once you created the token at [console.prod.ubirch.com](https://console.prod.ubirch.com) you need to copy it and flash it onto your device. Afterwards all the new sensor devices will automatically be added to your ubirch account and can be managed. 
>If you do not have a ubirch account, or cannot generate your own JWT Tokens, please contact us at [sales(at)ubirch.com](sales@ubirch.com) and we will take care of that.

Once you have your token, run the script:

```bash
$ python create_nvs_memory.py --stage demo --out gateway_memory.csv --token <insert your token string here>
```

## Create binary-file for NVS

Now you have a csv-file and can continue to create the nvs-flash-partition description binary-file (for more details compare
[the esp-idf documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/nvs_partition_gen.html)) by running:
```bash
$ python $IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py generate my_device_config.csv my_device_config.bin 0x3000
```

## Flash the partition to your device
To write the bin-file to your device run:
```bash
$ parttool.py write_partition --partition-name=nvs --input my_device_config.bin
```

## Read the partition from your device
To backup the whole configuration including the key-pairs, run:
```bash
$ parttool.py read_partition --partition-name=nvs --output my_device_config_backup.bin
```
