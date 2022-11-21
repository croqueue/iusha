#include "internal.h"

//====================//
// API IMPLEMENTATION //
//====================//

ShaComputationResult
sha1(
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

    if (message_len > SHA1_MAX_MSG_LEN)
        return UNSUPPORTED_DATA_SIZE;

    // Initialize hash
    uint32_t hash_words[5] = 
    {
        UINT32_C(0x67452301),
        UINT32_C(0xefcdab89),
        UINT32_C(0x98badcfe),
        UINT32_C(0x10325476),
        UINT32_C(0xc3d2e1f0)
    };

    // Compute digest
    compute_160(hash_words, message, message_len);
    
    // Format digest
    unpack_32(digest, hash_words, SHA1_DIGEST_LEN, format);    

    return HASH_COMPUTED;
}