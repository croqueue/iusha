#include "internal.h"

//====================//
// API IMPLEMENTATION //
//====================//

ShaComputationResult
sha384(
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

    // Initialize hash
    uint64_t hash_words[8] = 
    {
        UINT64_C(0xcbbb9d5dc1059ed8),
        UINT64_C(0x629a292a367cd507),
        UINT64_C(0x9159015a3070dd17),
        UINT64_C(0x152fecd8f70e5939),
        UINT64_C(0x67332667ffc00b31),
        UINT64_C(0x8eb44a8768581511),
        UINT64_C(0xdb0c2e0d64f98fa7),
        UINT64_C(0x47b5481dbefa4fa4)
    };

    // Compute digest
    compute_512(hash_words, message, message_len);

    // Format digest
    unpack_64(digest, hash_words, SHA384_DIGEST_LEN, format);

    return HASH_COMPUTED;
}
