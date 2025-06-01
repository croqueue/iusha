
//********************************************************//
//                                                        //
// libsharptwoth                                               //
//                                                        //
// Repository:  https://github.com/islandu/sharptwoth          //
// Author:      Daniel Thompson, Ph.D (2022)              //
// File:        src/sha224.c                              //
// Description: Implementation of sha224() hash function  //
//                                                        //
//********************************************************//

#include "sharptwoth/internal.h"

ShaComputationResult
sha224(
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

    if (message_len > SHA224_MAX_MSG_LEN)
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
        UINT32_C(0xc1059ed8),
        UINT32_C(0x367cd507),
        UINT32_C(0x3070dd17),
        UINT32_C(0xf70e5939),
        UINT32_C(0xffc00b31),
        UINT32_C(0x68581511),
        UINT32_C(0x64f98fa7),
        UINT32_C(0xbefa4fa4)
    };
    
    // Compute digest
    compute_256(hash_words, message, message_len);

    // Format digest
    unpack_32(digest, hash_words, SHA224_DIGEST_LEN, format);

    return HASH_COMPUTED;
}
