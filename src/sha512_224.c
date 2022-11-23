
//***********************************************************//
//                                                           //
// libiusha                                                  //
//                                                           //
// Repository:  https://github.com/islandu/iusha             //
// Author:      Daniel Thompson, Ph.D (2022)                 //
// File:        src/sha512_224.c                             //
// Description: Implementation of sha512_224() hash function //
//                                                           //
//***********************************************************//

#include "iusha/internal.h"

ShaComputationResult
sha512_224(
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
    uint64_t hash_words[8] = 
    {
        UINT64_C(0x8c3d37c819544da2),
        UINT64_C(0x73e1996689dcd4d6),
        UINT64_C(0x1dfab7ae32ff9c82),
        UINT64_C(0x679dd514582f9fcf),
        UINT64_C(0x0f6d2b697bd44da8),
        UINT64_C(0x77e36f7304c48942),
        UINT64_C(0x3f9d85a86a1d36c8),
        UINT64_C(0x1112e6ad91d692a1)
    };
    
    // Compute digest
    compute_512(hash_words, message, message_len);

    // Format digest
    unpack_64(digest, hash_words, SHA224_DIGEST_LEN, format);

    return HASH_COMPUTED;
}
