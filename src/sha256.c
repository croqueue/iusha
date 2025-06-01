
//********************************************************//
//                                                        //
// libsharptwoth                                               //
//                                                        //
// Repository:  https://github.com/islandu/sharptwoth          //
// Author:      Daniel Thompson, Ph.D (2022)              //
// File:        src/sha256.c                              //
// Description: Implementation of sha256() hash function  //
//                                                        //
//********************************************************//

#include "sharptwoth/internal.h"

ShaComputationResult
sha256(
    uint8_t * digest,
    const uint8_t * message,
    const uint64_t message_len,
    const ShaDigestFormat format
)
{
    // Validate arguments
    if (!digest)
        return NULL_DIGEST_POINTER;

    if (!message && message_len)
        return NULL_MESSAGE_POINTER;

    if (message_len > SHA256_MAX_MSG_LEN)
        return UNSUPPORTED_DATA_SIZE;
    
    switch (format)
    {
        case OCTET_ARRAY:
        case HEX_STRING_LOWER:
        case HEX_STRING_UPPER:
            break;
        default:
            return INVALID_DIGEST_FORMAT;
    }

    // Initialize hash
    uint32_t hash_words[8] = 
    {
        UINT32_C(0x6a09e667),
        UINT32_C(0xbb67ae85),
        UINT32_C(0x3c6ef372),
        UINT32_C(0xa54ff53a),
        UINT32_C(0x510e527f),
        UINT32_C(0x9b05688c),
        UINT32_C(0x1f83d9ab),
        UINT32_C(0x5be0cd19)
    };
    
    // Compute digest
    compute_256(hash_words, message, message_len);

    // Format digest
    unpack_32(digest, hash_words, SHA256_DIGEST_LEN, format);

    return HASH_COMPUTED;
}
