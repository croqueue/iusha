
//********************************************************//
//                                                        //
// libsharptwoth                                               //
//                                                        //
// Repository:  https://github.com/islandu/sharptwoth          //
// Author:      Daniel Thompson, Ph.D (2022)              //
// File:        src/compute.c                             //
// Description: Internal hash-computation functions       //
//                                                        //
//********************************************************//

#include "sharptwoth/internal.h"

//===========//
// Constants //
//===========//

static const uint32_t SHA1_CONSTANTS[4] =
{
    UINT32_C(0x5a827999), UINT32_C(0x6ed9eba1),
    UINT32_C(0x8f1bbcdc), UINT32_C(0xca62c1d6)
};

static const uint64_t SHA2_CONSTANTS[80] =
{
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

//==================//
// Static Functions //
//==================//

static uint64_t
pad_message_to_512(
    uint8_t * pad,
    const uint64_t message_len
);

static uint64_t
pad_message_to_1024(
    uint8_t * pad,
    const uint64_t message_len
);

static uint32_t
read_message_word_32(
    const uint8_t * data,
    const uint64_t data_length,
    const uint8_t * pad,
    const uint64_t block_index,
    const uint8_t word_index
);

static uint64_t
read_message_word_64(
    const uint8_t * data,
    const uint64_t data_length,
    const uint8_t * pad,
    const uint64_t block_index,
    const uint8_t word_index
);

static uint32_t
wrap_sum_32(int count, ...);

static uint64_t
wrap_sum_64(int count, ...);

static uint32_t
pack_32(const uint8_t * bytes);

static uint64_t
pack_64(const uint8_t * bytes);

//============================//
// Hash-Computation Functions //
//============================//

void
compute_160(
    uint32_t * hash_words, 
    const uint8_t * message, 
    const uint64_t message_len
)
{
    // Data pre-processing
    uint8_t pad[72] = { 0x00 };
    uint64_t block_count = pad_message_to_512(pad, message_len);

    // Message-block iteration
    uint32_t message_schedule[80] = { 0x00 };
    uint32_t a, b, c, d, e, tmp;
    uint8_t t;

    for (uint64_t i = 0; i < block_count; ++i)
    {
        // Message-schedule preparation
        // t = 0..16 (32-bit words from message block)
        for (t = 0; t < 16; ++t)
        {
            message_schedule[t] = 
                read_message_word_32(message, message_len, pad, i, t);
        }

        // t = 16..80
        for (; t < 80; ++t)
        {
            tmp = message_schedule[t - 3] 
                ^ message_schedule[t - 8] 
                ^ message_schedule[t - 14] 
                ^ message_schedule[t - 16];

            message_schedule[t] = ROTL(tmp, 1);
        }

        // Hash calculations
        a = hash_words[0];
        b = hash_words[1];
        c = hash_words[2];
        d = hash_words[3];
        e = hash_words[4];

        for (t = 0; t < 20; ++t)
        {
            tmp = wrap_sum_32(5,
                ROTL(a, 5),
                CH(b, c, d),
                e,
                SHA1_CONSTANTS[0],
                message_schedule[t]);
            
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = tmp;
        }

        for (; t < 40; ++t)
        {
            tmp = wrap_sum_32(5,
                ROTL(a, 5),
                PARITY(b, c, d),
                e,
                SHA1_CONSTANTS[1],
                message_schedule[t]);
            
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = tmp;
        }

        for (; t < 60; ++t)
        {
            tmp = wrap_sum_32(5,
                ROTL(a, 5),
                MAJ(b, c, d),
                e,
                SHA1_CONSTANTS[2],
                message_schedule[t]);
            
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = tmp;
        }

        for (; t < 80; ++t)
        {
            tmp = wrap_sum_32(5,
                ROTL(a, 5),
                PARITY(b, c, d),
                e,
                SHA1_CONSTANTS[3],
                message_schedule[t]);
            
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = tmp;
        }

        hash_words[0] = wrap_sum_32(2, hash_words[0], a);
        hash_words[1] = wrap_sum_32(2, hash_words[1], b);
        hash_words[2] = wrap_sum_32(2, hash_words[2], c);
        hash_words[3] = wrap_sum_32(2, hash_words[3], d);
        hash_words[4] = wrap_sum_32(2, hash_words[4], e);
    }
}

void
compute_256(
    uint32_t * hash_words, 
    const uint8_t * message, 
    const uint64_t message_len
)
{
    // Data pre-processing
    uint8_t pad[72] = { 0x00 };
    uint64_t block_count = pad_message_to_512(pad, message_len);

    // Message-block iteration
    uint32_t message_schedule[64] = { 0x00 };
    uint32_t a, b, c, d, e, f, g, h, tmp1, tmp2;
    uint8_t t;

    for (uint64_t i = 0; i < block_count; ++i)
    {
        // Message-schedule preparation
        // t = 0..16 (32-bit words from message block)
        for (t = 0; t < 16; ++t)
        {
            message_schedule[t] =
                read_message_word_32(message, message_len, pad, i, t);
        }

        // t = 16..64
        for (; t < 64; ++t)
        {
            message_schedule[t] = wrap_sum_32(4,
                LSIGMA1_256(message_schedule[t - 2]),
                message_schedule[t - 7],
                LSIGMA0_256(message_schedule[t - 15]),
                message_schedule[t - 16]);
        }

        // Hash calculations
        a = hash_words[0];
        b = hash_words[1];
        c = hash_words[2];
        d = hash_words[3];
        e = hash_words[4];
        f = hash_words[5];
        g = hash_words[6];
        h = hash_words[7];

        for (t = 0; t < 64; ++t)
        {
            tmp1 = wrap_sum_32(5,
                h,
                SIGMA1_256(e),
                CH(e, f, g),
                (uint32_t)(SHA2_CONSTANTS[t] >> 32),
                message_schedule[t]);

            tmp2 = wrap_sum_32(2, SIGMA0_256(a), MAJ(a, b, c));

            h = g;
            g = f;
            f = e;
            e = wrap_sum_32(2, d, tmp1);
            d = c;
            c = b;
            b = a;
            a = wrap_sum_32(2, tmp1, tmp2);
        }

        hash_words[0] = wrap_sum_32(2, hash_words[0], a);
        hash_words[1] = wrap_sum_32(2, hash_words[1], b);
        hash_words[2] = wrap_sum_32(2, hash_words[2], c);
        hash_words[3] = wrap_sum_32(2, hash_words[3], d);
        hash_words[4] = wrap_sum_32(2, hash_words[4], e);
        hash_words[5] = wrap_sum_32(2, hash_words[5], f);
        hash_words[6] = wrap_sum_32(2, hash_words[6], g);
        hash_words[7] = wrap_sum_32(2, hash_words[7], h);
    }
}

void
compute_512(
    uint64_t * hash_words, 
    const uint8_t * message, 
    const uint64_t message_len
)
{
    // Data pre-processing
    uint8_t pad[144] = { 0x00 };
    uint64_t block_count = pad_message_to_1024(pad, message_len);

    // Message-block iteration
    uint64_t message_schedule[80] = { 0x00 };
    uint64_t a, b, c, d, e, f, g, h, tmp1, tmp2;
    uint8_t t;

    for (uint64_t i = 0; i < block_count; ++i)
    {
        // Message-schedule preparation
        // t = 0..16 (64-bit words from message block)
        for (t = 0; t < 16; ++t)
        {
            message_schedule[t] = 
                read_message_word_64(message, message_len, pad, i, t);
        }

        // t = 16..80
        for (; t < 80; ++t)
        {
            message_schedule[t] = wrap_sum_64(4,
                LSIGMA1_512(message_schedule[t - 2]),
                message_schedule[t - 7],
                LSIGMA0_512(message_schedule[t - 15]),
                message_schedule[t - 16]);
        }

        // Hash calculations
        a = hash_words[0];
        b = hash_words[1];
        c = hash_words[2];
        d = hash_words[3];
        e = hash_words[4];
        f = hash_words[5];
        g = hash_words[6];
        h = hash_words[7];

        for (t = 0; t < 80; ++t)
        {
            tmp1 = wrap_sum_64(5,
                h,
                SIGMA1_512(e),
                CH(e, f, g),
                SHA2_CONSTANTS[t],
                message_schedule[t]);

            tmp2 = wrap_sum_64(2, SIGMA0_512(a), MAJ(a, b, c));

            h = g;
            g = f;
            f = e;
            e = wrap_sum_64(2, d, tmp1);
            d = c;
            c = b;
            b = a;
            a = wrap_sum_64(2, tmp1, tmp2);
        }

        hash_words[0] = wrap_sum_64(2, hash_words[0], a);
        hash_words[1] = wrap_sum_64(2, hash_words[1], b);
        hash_words[2] = wrap_sum_64(2, hash_words[2], c);
        hash_words[3] = wrap_sum_64(2, hash_words[3], d);
        hash_words[4] = wrap_sum_64(2, hash_words[4], e);
        hash_words[5] = wrap_sum_64(2, hash_words[5], f);
        hash_words[6] = wrap_sum_64(2, hash_words[6], g);
        hash_words[7] = wrap_sum_64(2, hash_words[7], h);
    }
}

//=======================//
// Misc Shared Functions //
//=======================//

void
unpack_32(
    uint8_t * buf, 
    const uint32_t * words, 
    const uint8_t byte_count, 
    const ShaDigestFormat format
)
{
    uint8_t word_index, pos_in_word, r_shift;

    if (!format)
    {
        for (uint8_t i = 0; i < byte_count; ++i)
        {
            word_index = i / 4;
            pos_in_word = i % 4;
            r_shift = (3 - pos_in_word) << 3;
            *(buf++) = (uint8_t)(words[word_index] >> r_shift);
        }

        return;
    }
    
    uint8_t byte, digit, a_add;

    a_add = (format == HEX_STRING_UPPER ? 'A' : 'a') - 10;

    for (uint8_t i = 0; i < byte_count; ++i)
    {
        word_index = i / 4;
        pos_in_word = i % 4;
        r_shift = (3 - pos_in_word) << 3;
        byte = (uint8_t)(words[word_index] >> r_shift);

        // Parse left hex digit
        digit = byte / 16;
        *(buf++) = digit + (digit < 10 ? '0' : a_add);

        // Parse right hex digit
        digit = byte % 16;
        *(buf++) = digit + (digit < 10 ? '0' : a_add);
    }

    *buf = '\0';
}

void
unpack_64(
    uint8_t * buf, 
    const uint64_t * words, 
    const uint8_t byte_count, 
    const ShaDigestFormat format
)
{
    uint8_t word_index, pos_in_word, r_shift;

    if (!format)
    {
        for (uint8_t i = 0; i < byte_count; ++i)
        {
            word_index = i / 8;
            pos_in_word = i % 8;
            r_shift = (7 - (pos_in_word)) << 3;
            *(buf++) = (uint8_t)(words[word_index] >> r_shift);
        }

        return;
    }

    uint8_t byte, digit, a_add;
    a_add = (format == HEX_STRING_UPPER ? 'A' : 'a') - 10;

    for (uint8_t i = 0; i < byte_count; ++i)
    {
        word_index = i / 8;
        pos_in_word = i % 8;
        r_shift = (7 - (pos_in_word)) << 3;
        byte = (uint8_t)(words[word_index] >> r_shift);

        // Parse left hex digit
        digit = byte / 16;
        *(buf++) = digit + (digit < 10 ? '0' : a_add);

        // Parse right hex digit
        digit = byte % 16;
        *(buf++) = digit + (digit < 10 ? '0' : a_add);
    }

    *buf = '\0';
}

//=============================//
// Static-Function Definitions //
//=============================//

static uint64_t
pad_message_to_512(
    uint8_t * pad,
    const uint64_t message_len
)
{
    // Complete blocks in message (prior to padding)
    uint64_t block_count = message_len / UINT64_C(64);

    uint8_t k, mod64;
    mod64 = (uint8_t)(message_len % UINT64_C(64));

    // k = number of 0x00 padding bytes
    // Increment block_count to reflect padding
    if (mod64 < 56)
    {
        k = 55 - mod64;
        ++block_count;
    }
    else
    {
        k = 119 - mod64;
        block_count += 2;
    }

    // Set 1 bit at start of pad
    pad[0] = 0x80;

    // Set message length in bits as last 64 bits of pad
    uint64_t bits = message_len << 3;
    unpack_64(pad + k + 1, &bits, 8, OCTET_ARRAY);

    // Return message block count (including padding)
    return block_count;
}

static uint64_t
pad_message_to_1024(
    uint8_t * pad,
    const uint64_t message_len
)
{
    // Complete blocks in message (prior to padding)
    uint64_t block_count = message_len / UINT64_C(128);

    uint8_t k, mod128;
    mod128 = (uint8_t)(message_len % UINT64_C(128));

    // k = number of 0x00 padding bytes
    // Increment block_count to reflect padding
    if (mod128 < 112)
    {
        k = 111 - mod128;
        ++block_count;
    }
    else
    {
        k = 239 - mod128;
        block_count += 2;
    }

    // Set 1 bit at start of pad
    pad[0] = 0x80;

    // Set message length in bits as last 128 bits of pad
    uint64_t bits[2] = 
    {
        (message_len & UINT64_C(0xE000000000000000)) >> 61,
        (message_len & SHA256_MAX_MSG_LEN) << 3
    };

    unpack_64(pad + k + 1, bits, 16, OCTET_ARRAY);

    // Return message block count (including padding)
    return block_count;
}

static uint32_t
read_message_word_32(
    const uint8_t * message,
    const uint64_t message_len,
    const uint8_t * pad,
    const uint64_t block_index,
    const uint8_t word_index
)
{
    uint64_t start_byte = (block_index * 64) + (word_index * 4);

    // Complete 32-bit word from input data
    if ((message_len >= 4) && (start_byte < message_len - 3))
        return pack_32(message + start_byte);

    // Complete 32-bit word from padding bytes
    if (start_byte >= message_len)
        return pack_32(pad + (start_byte - message_len));

    // 32-bit word that spans input data and padding bytes
    uint32_t word = 0;
    uint64_t message_index;
    uint8_t partial_len, byte_pos, l_shift;
    partial_len = (uint8_t)(message_len % 4);

    for (byte_pos = 0; byte_pos < partial_len; ++byte_pos)
    {
        message_index = message_len - partial_len + byte_pos;
        l_shift = (3 - byte_pos) << 3;
        word |= (uint32_t)message[message_index] << l_shift;
    }

    for (; byte_pos < 4; ++byte_pos)
    {
        l_shift = (3 - byte_pos) << 3;
        word |= (uint32_t)pad[byte_pos - partial_len] << l_shift;
    }
    
    return word;
    
}

static uint64_t
read_message_word_64(
    const uint8_t * message,
    const uint64_t message_len,
    const uint8_t * pad,
    const uint64_t block_index,
    const uint8_t word_index
)
{
    uint64_t start_byte = (block_index * 128) + (word_index * 8);

    // Complete 64-bit word from input data
    if ((message_len >= 8) && (start_byte < message_len - 7))
        return pack_64(message + start_byte);

    // Complete 64-bit word from padding bytes
    if (start_byte >= message_len)
        return pack_64(pad + (start_byte - message_len));

    // 64-bit word that spans input data and padding bytes
    uint64_t word = 0;
    uint64_t message_index;
    uint8_t partial_len, byte_pos, l_shift;
    partial_len = (uint8_t)(message_len % 8);

    for (byte_pos = 0; byte_pos < partial_len; ++byte_pos)
    {
        message_index = message_len - partial_len + byte_pos;
        l_shift = (7 - byte_pos) << 3;
        word |= (uint64_t)message[message_index] << l_shift;
    }

    for (; byte_pos < 8; ++byte_pos)
    {
        l_shift = (7 - byte_pos) << 3;
        word |= (uint64_t)pad[byte_pos - partial_len] << l_shift;
    }
    
    return word;
}

static uint32_t
wrap_sum_32(int count, ...)
{
    va_list arg_list;
    uint32_t sum = 0, addend, overflow_thresh;

    va_start(arg_list, count);

    for (int i = 0; i < count; ++i)
    {
        addend = va_arg(arg_list, uint32_t);

        if (!addend)
            continue;

        if (!sum)
        {
            sum = addend;
            continue;
        }

        // Determine minimum addend that would cause overflow
        overflow_thresh = UINT32_MAX - sum + 1;

        // If sum will overflow, assign difference of addend & overflow_addend
        // (Equivalent to addition modulo 2^32)
        sum = (addend >= overflow_thresh) 
            ? (addend - overflow_thresh) 
            : (sum + addend);
    }

    va_end(arg_list);
    return sum;
}

static uint64_t
wrap_sum_64(int count, ...)
{
    va_list arg_list;
    uint64_t sum = 0, addend, overflow_thresh;

    va_start(arg_list, count);

    for (int i = 0; i < count; ++i)
    {
        addend = va_arg(arg_list, uint64_t);

        if (!addend)
            continue;

        if (!sum)
        {
            sum = addend;
            continue;
        }

        // Determine minimum addend that would cause overflow
        overflow_thresh = UINT64_MAX - sum + 1;

        // If sum will overflow, assign difference of addend & overflow_addend
        // (Equivalent to addition modulo 2^64)
        sum = (addend >= overflow_thresh) 
            ? (addend - overflow_thresh) 
            : (sum + addend);
    }

    va_end(arg_list);
    return sum;
}

static uint32_t
pack_32(const uint8_t * bytes)
{
    uint32_t word = 0;
    uint8_t l_shift;

    for (uint8_t i = 0; i < 4; ++i)
    {
        l_shift = (3 - i) << 3;
        word |= (uint32_t)bytes[i] << l_shift;
    }

    return word;
}

static uint64_t
pack_64(const uint8_t * bytes)
{
    uint64_t word = 0;
    uint8_t l_shift;

    for (uint8_t i = 0; i < 8; ++i)
    {
        l_shift = (7 - i) << 3;
        word |= (uint64_t)bytes[i] << l_shift;
    }

    return word;
}
