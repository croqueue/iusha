#include <stdbool.h>
#include <stdio.h>
#include "iusha/iusha.h"
#include "iusha/tests/helpers.h"

static const char * expected_digests[5] = 
{
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    "a49b2446a02c645bf419f995b67091253a04a259",
    "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
};

int main()
{
    bool success = true;

    TestContext * contexts[5] = { NULL };

    for (int i = 0; i < 5; ++i)
    {
        contexts[i] = TestContext_Init(
            i + 1, 
            expected_digests[i], 
            SHA1_DIGEST_LEN
        );
        
        success = success && TestContext_RunGeneric(contexts[i], SHA1);
        TestContext_Free(contexts[i]);
    }

    return success ? 0 : -1;
}
