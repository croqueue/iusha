
//***********************************************************//
//                                                           //
// libiusha                                                  //
//                                                           //
// Repository:  https://github.com/islandu/iusha             //
// Author:      Daniel Thompson, Ph.D (2022)                 //
// File:        src/sha.c                                    //
// Description: Implementation of master sha() hash function //
//                                                           //
//***********************************************************//

#include "iusha/internal.h"

ShaComputationResult
sha(
    ShaType algorithm,
    uint8_t * digest, 
    const uint8_t * message, 
    const uint64_t message_len,
    const ShaDigestFormat format
)
{
    hasher_t hasher;

    switch (algorithm)
    {
        case SHA1:
            hasher = sha1;
            break;
        case SHA224:
            hasher = sha224;
            break;
        case SHA256:
            hasher = sha256;
            break;
        case SHA384:
            hasher = sha384;
            break;
        case SHA512:
            hasher = sha512;
            break;
        case SHA512_224:
            hasher = sha512_224;
            break;
        case SHA512_256:
            hasher = sha512_256;
            break;
        default:
            return INVALID_ALGORITHM;
    }

    return hasher(digest, message, message_len, format);
}