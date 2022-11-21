#include "internal.h"

//====================//
// API IMPLEMENTATION //
//====================//

ShaComputationResult
sha512(
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
        UINT64_C(0x6a09e667f3bcc908),
        UINT64_C(0xbb67ae8584caa73b),
        UINT64_C(0x3c6ef372fe94f82b),
        UINT64_C(0xa54ff53a5f1d36f1),
        UINT64_C(0x510e527fade682d1),
        UINT64_C(0x9b05688c2b3e6c1f),
        UINT64_C(0x1f83d9abfb41bd6b),
        UINT64_C(0x5be0cd19137e2179)
    };
    
    // Compute digest
    compute_512(hash_words, message, message_len);

    // Format digest
    unpack_64(digest, hash_words, SHA512_DIGEST_LEN, format);

    return HASH_COMPUTED;
}
