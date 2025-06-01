#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sharptwoth/tests/helpers.h"

static const char * MESSAGE_PATHS = "./data/message%d.txt";
static const char * HASH_PATHS = "./data/%s_hashes.txt";
static const char * MESSAGE_READ_FAIL = "Failed to load test message from file '%s'\n";
static const char * DIGEST_READ_FAIL = "Failed to load expected hash digests from file '%s'\n";

static const char * HASH_MISMATCH = 
    "Computed hash digest of file '%s' does not match the expected value\n"
    "---EXPECTED: %s\n"
    "---COMPUTED: %s\n\n";

static const char * ALGORITHM_STRINGS[7] =
{
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512_224",
    "sha512_256"
};

static void
hex_to_bytes(uint8_t * dest, const char * hex, uint8_t byte_count);

static bool
sequence_equal(const uint8_t * a, const uint8_t * b, const uint8_t len);

TestContext * 
TestContext_Init(
    const int test_message_number,
    const char * expected_hex_lower,
    const uint8_t digest_len
)
{
    TestContext * context = calloc(1, sizeof(TestContext));

    if (!context)
        return NULL;
    
    sprintf(context->file_path, MESSAGE_PATHS, test_message_number);

    FILE * file_handle = fopen(context->file_path, "r");

    if (!file_handle)
    {
        printf(MESSAGE_READ_FAIL, context->file_path);
        return NULL;
    }
    
    fseek(file_handle, 0L, SEEK_END);
    context->file_size = (uint64_t)ftell(file_handle);
    context->file_contents = calloc(context->file_size + 1, sizeof(char));

    if (!context->file_contents)
    {
        printf(MESSAGE_READ_FAIL, context->file_path);
        return NULL;
    }
    
    fseek(file_handle, 0L, SEEK_SET);

    int c;
    uint64_t file_pos = 0;

    while ((c = fgetc(file_handle)) != EOF)
    {
        context->file_contents[file_pos++] = (char)c;
    }

    fclose(file_handle);
    
    uint8_t hex_len = digest_len * 2;

    context->expected_hashes.digest_len = digest_len;
    context->actual_hashes.digest_len = digest_len;
    strcpy(context->expected_hashes.hex_lower, expected_hex_lower);
    
    for (int i = 0; i < hex_len + 1; ++i)
        context->expected_hashes.hex_upper[i] = toupper(expected_hex_lower[i]);

    hex_to_bytes(context->expected_hashes.raw, expected_hex_lower, digest_len);

    return context;
}

bool
TestContext_Run(TestContext * context, hasher_t hash_function)
{
    if (!context || !hash_function)
        return false;

    context->results[0] = hash_function(
        context->actual_hashes.raw, 
        context->file_contents, 
        context->file_size, 
        OCTET_ARRAY
    );
    
    context->results[1] = hash_function(
        context->actual_hashes.hex_lower,
        context->file_contents,
        context->file_size,
        HEX_STRING_LOWER
    );

    context->results[2] = hash_function(
        context->actual_hashes.hex_upper,
        context->file_contents,
        context->file_size,
        HEX_STRING_UPPER
    );

    context->match[0] = sequence_equal(
        context->expected_hashes.raw, 
        context->actual_hashes.raw, 
        context->expected_hashes.digest_len
    );

    context->match[1] = !strcmp(
        context->expected_hashes.hex_lower, 
        context->actual_hashes.hex_lower
    );

    context->match[2] = !strcmp(
        context->expected_hashes.hex_upper, 
        context->actual_hashes.hex_upper
    );
    
    if (context->match[0] && context->match[1] && context->match[2])
    {
        return true;
    }
    else
    {
        printf(HASH_MISMATCH, 
            context->file_path, 
            context->expected_hashes.hex_lower, 
            context->actual_hashes.hex_lower);
        
        return false;
    }
}

bool
TestContext_RunGeneric(TestContext * context, ShaType algorithm)
{
    if (!context)
        return false;
    
    context->results[0] = sha(
        algorithm,
        context->actual_hashes.raw, 
        context->file_contents, 
        context->file_size, 
        OCTET_ARRAY
    );
    
    context->results[1] = sha(
        algorithm,
        context->actual_hashes.hex_lower,
        context->file_contents,
        context->file_size,
        HEX_STRING_LOWER
    );

    context->results[2] = sha(
        algorithm,
        context->actual_hashes.hex_upper,
        context->file_contents,
        context->file_size,
        HEX_STRING_UPPER
    );

    context->match[0] = sequence_equal(
        context->expected_hashes.raw, 
        context->actual_hashes.raw, 
        context->expected_hashes.digest_len
    );

    context->match[1] = !strcmp(
        context->expected_hashes.hex_lower, 
        context->actual_hashes.hex_lower
    );

    context->match[2] = !strcmp(
        context->expected_hashes.hex_upper, 
        context->actual_hashes.hex_upper
    );

    if (context->match[0] && context->match[1] && context->match[2])
    {
        return true;
    }
    else
    {
        printf(HASH_MISMATCH, 
            context->file_path, 
            context->expected_hashes.hex_lower, 
            context->actual_hashes.hex_lower);
        
        return false;
    }
}

void
TestContext_Free(TestContext * context)
{
    free(context->file_contents);
    free(context);
}

bool
load_expected_digests(char hashes[NUM_TESTS][HEX_DIGEST_BUFFER_LEN], ShaType algorithm)
{
    char file_path[30] = { '\0' };
    sprintf(file_path, HASH_PATHS, ALGORITHM_STRINGS[algorithm]);

    FILE * file_handle = fopen(file_path, "r");

    if (!file_handle)
    {
        printf(DIGEST_READ_FAIL, file_path);
        return false;
    }
    
    memset(hashes, '\0', NUM_TESTS * HEX_DIGEST_BUFFER_LEN);
    
    int c;

    for (int i = 0; i < NUM_TESTS; ++i)
    {
        int j = 0;

        while ((c = fgetc(file_handle)) != EOF)
        {
            if (c == '\n')
                break;

            hashes[i][j++] = (char)c;
        }
    }

    fclose(file_handle);
    return true;
}

static void
hex_to_bytes(uint8_t * dest, const char * hex, uint8_t byte_count)
{
    char c;
    uint8_t byte;

    for (uint8_t i = 0; i < byte_count; ++i)
    {
        byte = 0x00;

        for (uint8_t j = 0; j < 2; ++j)
        {
            byte *= 16;
            c = tolower(*hex++);
            byte += c - (c <= '9' ? '0': 'a' - 10);
        }

        dest[i] = byte;
    }
}

static bool
sequence_equal(const uint8_t * a, const uint8_t * b, const uint8_t len)
{
    for (uint8_t i = 0; i < len; ++i)
    {
        if (a[i] != b[i])
            return false;
    }

    return true;
}
