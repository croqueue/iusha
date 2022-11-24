#include <stdbool.h>
#include "iusha/tests/helpers.h"

int main()
{
    char expected_digests[NUM_TESTS][HEX_DIGEST_BUFFER_LEN];

    if (!load_expected_digests(expected_digests, SHA512_256))
        return -1;

    TestContext * context = NULL;
    bool success = true;

    for (int i = 0; i < NUM_TESTS; ++i)
    {
        context = TestContext_Init(
            i + 1, 
            expected_digests[i], 
            SHA512_256_DIGEST_LEN
        );

        if (!context)
            return -1;
        
        success = success && TestContext_Run(context, sha512_256);
        TestContext_Free(context);
        context = NULL;
    }

    return success ? 0 : -1;
}
