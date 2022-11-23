#ifndef IUSHA_TESTS_INTERNAL_H
#define IUSHA_TESTS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "iusha/iusha.h"

// HashDigests
// Structure for capturing multiple formats of a single message digest
typedef struct HashDigests
{
    uint8_t digest_len;
    uint8_t raw[SHA512_DIGEST_LEN];
    char hex_lower[SHA512_DIGEST_LEN * 2 + 1];
    char hex_upper[SHA512_DIGEST_LEN * 2 + 1];

} HashDigests;

// TestContext
// Structure for managing a test instance's input and output
typedef struct TestContext
{
    char file_path[40];
    uint64_t file_size;
    char * file_contents;
    HashDigests expected_hashes;
    HashDigests actual_hashes;
    ShaComputationResult results[3];
    bool match[3];

} TestContext;


// TestContext_Init()
// Allocates and initializes a TestContext structure
TestContext * 
TestContext_Init(
    const int test_message_number,
    const char * expected_hex_lower,
    const uint8_t digest_len
);

// TestContext_Run()
// Executes test instance with one of the non-generic hashing function
bool
TestContext_Run(TestContext * context, hasher_t hash_function);


bool
TestContext_RunGeneric(TestContext * context, ShaType algorithm);

void
TestContext_Free(TestContext * context);

#endif // IUSHA_TESTS_INTERNAL_H