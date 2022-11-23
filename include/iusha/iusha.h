
//********************************************************//
//                                                        //
// libiusha                                               //
//                                                        //
// Repository:  https://github.com/islandu/iusha          //
// Author:      Daniel Thompson, Ph.D (2022)              //
// File:        include/iusha/iusha.h                     //
// Description: Public API specification                  //
//                                                        //
//********************************************************//

#ifndef IUSHA_H
#define IUSHA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ShaType
// Enum indicating which secure hash algorithm to compute for master sha() function
//
// Members:
//   SHA1      
//   SHA224    
//   SHA256    
//   SHA384    
//   SHA512    
//   SHA512_224
//   SHA512_256

typedef enum {
    SHA1        = 0,
    SHA224      = 1,
    SHA256      = 2,
    SHA384      = 3,
    SHA512      = 4,
    SHA512_224  = 5,
    SHA512_256  = 6

} ShaType;

// ShaComputationResult
// Enum returned from hash-computation functions to indicate success or reason for failure
// 
// Members:
//   HASH_COMPUTED          Selected algorithm executed successfully
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

// hasher_t
// Function-pointer type that matches the non-generic hashing functions' signatures
typedef ShaComputationResult (* hasher_t)(
    uint8_t *, 
    const uint8_t *, 
    const uint64_t, 
    const ShaDigestFormat
);

// sha1()
// Populates a buffer with the SHA-1 hash digest for the given message input
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data (cannot be greater than 2^61)
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha1(
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

// sha224()
// Populates a buffer with the SHA-224 hash digest for the given message input
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data (cannot be greater than 2^61)
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha224(
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

// sha256()
// Populates a buffer with the SHA-256 hash digest for the given message input
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data (cannot be greater than 2^61)
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha256(
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

// sha384()
// Populates a buffer with the SHA-384 hash digest for the given message input
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha384(
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

// sha512()
// Populates a buffer with the SHA-512 hash digest for the given message input
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha512(
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

// sha512_224()
// Populates a buffer with the SHA-512 hash digest for the given message input
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha512_224(
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

// sha512_256()
// Populates a buffer with the SHA-512 hash digest for the given message input
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha512_256(
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

// sha()
// Generic function for which the caller specifies the SHA-X algorithm to compute
//
// Return value:
//     ShaComputationResult enum indicating successful hash computation or reason for error
//
// Parameters:
//     digest       Pointer to destination buffer for hash digest
//     message      Pointer to input data
//     message_len  Number of bytes in input data
//     format       Enum indicating digest format (raw bytes, uppercase/lowercase hexadecimal)

ShaComputationResult
sha(
    ShaType algorithm,
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
);

//=================//
// MACRO CONSTANTS //
//=================//

// Hash-digest lengths in bytes 
#define SHA1_DIGEST_LEN         20
#define SHA224_DIGEST_LEN       28
#define SHA256_DIGEST_LEN       32
#define SHA384_DIGEST_LEN       48
#define SHA512_DIGEST_LEN       64
#define SHA512_224_DIGEST_LEN   28
#define SHA512_256_DIGEST_LEN   32

// Data size limits (roughly 16,777,215 TiB for SHA-1/SHA-224/SHA-256)
// Can't possibly reach this limit with in-memory buffer
// (But a bad length calculation may still be caught)
#define SHA1_MAX_MSG_LEN    UINT64_C(0x1fffffffffffffff)
#define SHA224_MAX_MSG_LEN  UINT64_C(0x1fffffffffffffff)
#define SHA256_MAX_MSG_LEN  UINT64_C(0x1fffffffffffffff)

// Note:
// Limitations on memory apply even more so to max lengths for SHA-384, SHA-512, and SHA-512/T
// Max data length for these algorithms is 2^128 - 1 bits
// This library handles data lengths with unsigned 64-bit integers (max value = 2^64-1)
// So there is no need to define data limits for these algorithms

#ifdef __cplusplus
}
#endif

#endif // IUSHA_H
