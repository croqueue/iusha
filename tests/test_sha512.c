#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "iusha/iusha.h"
#include "internal.h"

extern char * test_messages[5];

int main()
{
    load_test_messages();

    // Load expected hashes
    char expected_hashes[5][SHA512_DIGEST_LEN * 2 + 1] = { '\0' };

    char file_path[27] = { '\0' };
    FILE * file_handle;

    for (int i = 0; i < 5; ++i)
    {
        sprintf(file_path, "./data/message%d/sha512.txt", i + 1);
        file_handle = fopen(file_path, "r");
        fgets(expected_hashes[i], SHA512_DIGEST_LEN * 2 + 1, file_handle);
        fclose(file_handle);
    }

    char actual_hashes[5][SHA512_DIGEST_LEN * 2 + 1];

    for (int i = 0; i < 5; ++i)
    {
        sha512(actual_hashes[i], test_messages[i], strlen(test_messages[i]), HEX_STRING_LOWER);
        assert(!strcmp(expected_hashes[i], actual_hashes[i]));
    }

    return 0;
}
