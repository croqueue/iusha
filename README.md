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
`libiusha` was designed to be very easy to use and work solely with input data held in RAM (e.g., small- to medium-sized files that will fit in memory, ASCII/UTF-8 strings, etc.). If incremental computation of hash digests of large amounts of data via streams is needed, you may want to go with another library.

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

### Example Code
The example program below calculates and prints the SHA-256 hash for a UTF-8 string and a file read into memory.

```c
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include "iusha/iusha.h"

static bool
load_file(uint8_t * file_buffer, const char * file_path, uint64_t * file_size);

int main()
{
    const char * input_str = "The trüth is öut there";
    uint8_t input_file[4096];
    uint64_t file_size;

    // Buffers for raw hash bytes
    uint8_t str_hash_bytes[SHA256_DIGEST_LEN];
    uint8_t file_hash_bytes[SHA256_DIGEST_LEN];

    // Buffers for hashes as hexadecimal strings
    char str_hash_hex[SHA256_DIGEST_LEN * 2 + 1];
    char file_hash_hex[SHA256_DIGEST_LEN * 2 + 1];

    // Load file into memory
    if (!load_file(input_file, "/path/to/file", &file_size))
        return -1;

    // Compute hashes in raw bytes
    sha256(str_hash_bytes, input_str, strlen(input_str), OCTET_ARRAY);
    sha256(file_hash_bytes, input_file, file_size, OCTET_ARRAY);

    // Compute hashes in hexadecimal format (lowercase)
    sha256(str_hash_hex, input_str, strlen(input_str), HEX_STRING_LOWER);
    sha256(file_hash_hex, input_file, file_size, HEX_STRING_LOWER);

    printf("SHA-256 hash of 'input_str' (hexadecimal lowercase):\n%s\n", str_hash_hex);
    printf("SHA-256 hash of 'input_file' (hexadecimal lowercase):\n%s\n", file_hash_hex);

    // Compute hashes in hexadecimal format (uppercase)
    sha256(str_hash_hex, input_str, strlen(input_str), HEX_STRING_UPPER);
    sha256(file_hash_hex, input_file, file_size, HEX_STRING_UPPER);

    printf("SHA-256 hash of 'input_str' (hexadecimal uppercase):\n%s\n", str_hash_hex);
    printf("SHA-256 hash of 'input_file' (hexadecimal uppercase):\n%s\n", file_hash_hex);

    return 0;
}

static bool
load_file(uint8_t * file_buffer, const char * file_path, uint64_t * file_size)
{
    *file_size = 0;
    FILE * file_handle = fopen(file_path, "rb");

    if (!file_handle)
        return false;
    
    int byte;

    while ((byte = fgetc(file_handle)) != EOF)
    {
        file_buffer[(*file_size)++] = (uint8_t)byte;
    }

    return true;
}
```

## External Resources
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
