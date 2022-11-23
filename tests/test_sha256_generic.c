#include <stdbool.h>
#include "iusha/iusha.h"
#include "iusha/tests/helpers.h"

static const char * expected_digests[5] = 
{
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
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
            SHA256_DIGEST_LEN
        );
        
        success = success && TestContext_RunGeneric(contexts[i], SHA256);
        TestContext_Free(contexts[i]);
    }

    return success ? 0 : -1;
}
