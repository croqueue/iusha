#include <stdio.h>
#include "internal.h"

char message1[4] = { '\0' };
char message2[1] = { '\0' };
char message3[57] = { '\0' };
char message4[113] = { '\0' };
char message5[1000001] = { '\0' };

char * test_messages[5] = 
{
    message1,
    message2,
    message3,
    message4,
    message5
};

int buffer_sizes[5] = { 4, 1, 57, 113, 1000001 };

void load_test_messages()
{
    char file_path[28] = { '\0' };
    FILE * file_handle;

    for (int i = 0; i < 5; ++i)
    {
        sprintf(file_path, "./data/message%d/message.txt", i + 1);
        file_handle = fopen(file_path, "r");
        fgets(test_messages[i], buffer_sizes[i], file_handle);
        fclose(file_handle);
    }
}
