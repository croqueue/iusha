#ifndef IUSHA_TESTS_HELPERS_H
#define IUSHA_TESTS_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "iusha/iusha.h"

#define NUM_TESTS 5
#define HEX_DIGEST_BUFFER_LEN 129

// HashDigests
// Structure for capturing multiple formats of a single message digest
typedef struct HashDigests
{
    uint8_t digest_len;
    uint8_t raw[SHA512_DIGEST_LEN];
    char hex_lower[HEX_DIGEST_BUFFER_LEN];
    char hex_upper[HEX_DIGEST_BUFFER_LEN];

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
// Allocates and initializes a TestContext structure with data from test files
TestContext * 
TestContext_Init(
    const int test_message_number,
    const char * expected_hex_lower,
    const uint8_t digest_len
);

// TestContext_Run()
// Executes test instance with one of the non-generic hashing functions
bool
TestContext_Run(TestContext * context, hasher_t hash_function);

// TestContext_Run()
// Executes test instance with one of the sha() generic hashing function
bool
TestContext_RunGeneric(TestContext * context, ShaType algorithm);

// TestContext_Free()
// Releases RAM used by TestContext instance
void
TestContext_Free(TestContext * context);

// load_expected_digests()
// Reads expected hash digests for a particular algorithm from files
bool
load_expected_digests(char hashes[NUM_TESTS][HEX_DIGEST_BUFFER_LEN], ShaType algorithm);

#endif // IUSHA_TESTS_HELPERS_H
