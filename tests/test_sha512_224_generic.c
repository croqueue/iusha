#include <stdbool.h>
#include "iusha/iusha.h"
#include "iusha/tests/helpers.h"

static const char * expected_digests[5] = 
{
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
    "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174",
    "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
    "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287"
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
            SHA512_224_DIGEST_LEN
        );
        
        success = success && TestContext_RunGeneric(contexts[i], SHA512_224);
        TestContext_Free(contexts[i]);
    }

    return success ? 0 : -1;
}
