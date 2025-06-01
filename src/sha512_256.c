
//***********************************************************//
//                                                           //
// libsharptwoth                                                  //
//                                                           //
// Repository:  https://github.com/croqueue/sharptwoth             //
// Author:      Danielle Thompson, Ph.D (2022)                 //
// File:        src/sha512_256.c                             //
// Description: Implementation of sha512_256() hash function //
//                                                           //
//***********************************************************//

#include "sharptwoth/internal.h"

ShaComputationResult
sha512_256(
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
        UINT64_C(0x22312194fc2bf72c),
        UINT64_C(0x9f555fa3c84c64c2),
        UINT64_C(0x2393b86b6f53b151),
        UINT64_C(0x963877195940eabd),
        UINT64_C(0x96283ee2a88effe3),
        UINT64_C(0xbe5e1e2553863992),
        UINT64_C(0x2b0199fc2c85b8aa),
        UINT64_C(0x0eb72ddc81c52ca2)
    };

    // Compute digest
    compute_512(hash_words, message, message_len);

    // Format digest
    unpack_64(digest, hash_words, SHA256_DIGEST_LEN, format);

    return HASH_COMPUTED;
}
