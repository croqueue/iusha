#include <stdbool.h>
#include "iusha/iusha.h"
#include "iusha/tests/helpers.h"

static const char * expected_digests[5] = 
{
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
    "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
    "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
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
            SHA224_DIGEST_LEN
        );
        
        success = success && TestContext_RunGeneric(contexts[i], SHA224);
        TestContext_Free(contexts[i]);
    }

    return success ? 0 : -1;
}
