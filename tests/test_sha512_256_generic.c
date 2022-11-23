#include <stdbool.h>
#include "iusha/iusha.h"
#include "iusha/tests/helpers.h"

static const char * expected_digests[5] = 
{
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
    "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
    "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21"
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
            SHA512_256_DIGEST_LEN
        );
        
        success = success && TestContext_RunGeneric(contexts[i], SHA512_256);
        TestContext_Free(contexts[i]);
    }

    return success ? 0 : -1;
}
