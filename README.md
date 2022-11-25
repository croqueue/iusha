# libiusha
## Description
A simple-to-use C library implementing the first- and second-generation Secure Hashing Algorithms (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256). `libiusha` has no dependencies beyond the C standard library and no memory is allocated on the heap internally. All hash digests are computed via a single call to one of the seven hashing functions, for which the caller provides a byte array containing the input message and an adequate buffer to populate the resulting hash digest. 

## Disclaimer
I permit any and all use of this code, but I make no guarantees...and let's face it this was really just an exercise to combat my own boredom late at night.

## Compilation (Linux)

Clone the source code and navigate to the `iusha` root directory.
```
$ cd local/path/to/iusha
```
Create a `build` directory and navigate to it.
```
$ mkdir build && cd $_
```
Once in the build directory, configure CMake and compile the library.
```
$ cmake ..
$ cmake --build .
```
While still in the `build` directory, run the unit tests to make sure everything is kosher.
```
$ ctest
```
If some of the unit tests fail, run them again with the `--verbose` flag to troubleshoot.
```
$ ctest --verbose
```

## Documentation
`libiusha` was designed to be very easy to use and to work solely with input data held in RAM (e.g., small- to medium-sized files that will fit in memory, ASCII/UTF-8 strings, etc.). If incremental computation of hash digests of large amounts of data via streams is needed, you may want to go with another library (but future enhancements to this library may include that functionality).

### Library Functions
There are two options for hash computation. Callers can either call the generic `sha()` function and specify the algorithm used for computation in the first argument or call the function for the desired algorithm directly (`sha1()`, `sha224()`, `sha256()`, `sha384()`, `sha512()`, `sha512_224()`, `sha512_256()`).

### Hash Format
Callers must provide an ample `uint8_t` buffer for population of the hash digest by the hashing functions, but there are three options for the format of the hash digest (specified with `ShaDigestFormat format` argument).

```c
// ShaDigestFormat
// Enum that selects the output format for hashing functions
//
// Values:
//   OCTET_ARRAY        Digest represented without encoding
//   HEX_STRING_LOWER   Lowercase hex encoding of digest (null-terminated)
//   HEX_STRING_UPPER   Uppercase hex encoding of digest (null-terminated)

typedef enum {

    OCTET_ARRAY         = 0,
    HEX_STRING_LOWER    = 1,
    HEX_STRING_UPPER    = 2

} ShaDigestFormat;
```

### Response Codes
The hashing functions populate the `digest` buffer with the computed hash digest and each function returns a member of the `ShaComputationResult` enum to indicate success or the reason for failure.

```c
// ShaComputationResult
// Enum returned from hash-computation functions to indicate success or reason for failure
// 
// Members:
//   HASH_COMPUTED          Selected algorithm executed successfully
//   INVALID_ALGORITHM      Unrecognized value for 'algorithm' argument passed to sha()
//   INVALID_DIGEST_FORMAT  Unrecognized value for 'format' argument passed to hasing function
//   UNSUPPORTED_DATA_SIZE  Input data too large (SHA-1/SHA-256/SHA-224)
//   NULL_MESSAGE_POINTER   Pointer to input data is NULL (length indicated as > 0)
//   NULL_DIGEST_POINTER    Pointer to output buffer is NULL

typedef enum {

    HASH_COMPUTED           = 0,
    INVALID_ALGORITHM       = 1,
    INVALID_DIGEST_FORMAT   = 2,
    UNSUPPORTED_DATA_SIZE   = 3,
    NULL_MESSAGE_POINTER    = 4,
    NULL_DIGEST_POINTER     = 5

} ShaComputationResult;
```

### Hashing Files or Byte Arrays (using `sha256()` function)
Prior to hash computation, you will need to load the file into memory, e.g.:
```c
// #include <stdio.h>
// #include "iusha/iusha.h"

uint8_t file_contents[4096];
uint64_t file_size = 0;
const char * file_path = "path/to/your/file";

// Open file in "read binary" mode so the bytes are read without transformation
FILE * file_handle = fopen(file_path, "rb");

if (!file_handle)
{
    printf("Could not open file '%s'\n", file_path);
    // Perform any other appropriate actions on failure
}

int byte;

while ((byte = fgetc(file_handle)) != EOF)
{
    file_contents[file_size++] = (uint8_t)byte;
}

fclose(file_handle)
```
If you just want the raw bytes of the hash digest, create a `uint8_t` buffer using the appropriate macro constant from `iusha.h`. Then call the hashing function and pass `OCTET_ARRAY` as the argument for the `format` parameter.
```c
// #include "iusha/iusha.h"

uint8_t hash_bytes[SHA256_DIGEST_LEN];
ShaComputationResult result;

result = sha256(hash_bytes, file_contents, file_size, OCTET_ARRAY);

if (result != HASH_COMPUTED)
{
    // Something went wrong
}
```
If you prefer the hash digest to be formatted as a hexadecimal string, create a `char` buffer using the appropriate macro constant from `iusha.h`, but double its size and add 1 for the null terminator. Then call the hashing function and pass either `HEX_STRING_LOWER` or `HEX_STRING_UPPER` as the argument for the `format` parameter.
```c
// #include "iusha/iusha.h"

// Double the hash-digest length and add 1 for the null terminator
char hash_hex[SHA256_DIGEST_LEN * 2 + 1];
ShaComputationResult result;

// Lowercase hexadecimal string
result = sha256(hash_hex, file_contents, file_size, HEX_STRING_LOWER);
// Uppercase hexadecimal string
result = sha256(hash_hex, file_contents, file_size, HEX_STRING_UPPER);

if (result != HASH_COMPUTED)
{
    // Something went wrong
}
```

### Hashing Strings (using `sha256()` function)
ASCII/UTF-8 strings can be hashed directly. If you are working with strings that use a different encoding (e.g., UTF-16LE, UTF-32) and the contents are not stored in an array of an 8-bit type (e.g. `wchar_t`), you will have to perform some pre-processing to flatten the data into an array of bytes (and a simple internet search can help you there). The examples below will use a UTF-8 string as the input message.

If you just want the raw bytes of the hash digest, create a `uint8_t` buffer using the appropriate macro constant from `iusha.h`. Then call the hashing function and pass `OCTET_ARRAY` as the argument for the `format` parameter.
```c
// #include <string.h>
// #include "iusha/iusha.h"

const char * utf8_str = "The trüth is öut there";
uint8_t hash_bytes[SHA256_DIGEST_LEN];
ShaComputationResult result;

result = sha256(hash_bytes, utf8_str, strlen(utf8_str), OCTET_ARRAY);

if (result != HASH_COMPUTED)
{
    // Something went wrong
}
```
If you prefer the hash digest to be formatted as a hexadecimal string, create a `char` buffer using the appropriate macro constant from `iusha.h`, but double its size and add 1 for the null terminator. Then call the hashing function and pass either `HEX_STRING_LOWER` or `HEX_STRING_UPPER` as the argument for the `format` parameter.
```c
// #include <string.h>
// #include "iusha/iusha.h"

const char * utf8_str = "The trüth is öut there";

// Double the hash-digest length and add 1 for the null terminator
char hash_hex[SHA256_DIGEST_LEN * 2 + 1];
ShaComputationResult result;

// Lowercase hexadecimal string
result = sha256(hash_hex, utf8_str, strlen(utf8_str), HEX_STRING_LOWER);
// Uppercase hexadecimal string
result = sha256(hash_hex, utf8_str, strlen(utf8_str), HEX_STRING_UPPER);

if (result != HASH_COMPUTED)
{
    // Something went wrong
}
```

## External Resources
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
