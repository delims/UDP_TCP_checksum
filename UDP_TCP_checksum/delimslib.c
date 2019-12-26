//
//  delimslib.c
//  UDP_TCP_checksum
//
//  Created by delims on 2019/12/25.
//  Copyright © 2019 delims. All rights reserved.
//

#include "delimslib.h"
#include <string.h>

char char_to_long(char ch, unsigned long *i)
{
    if (ch <= '9' && ch >= '0') {
        *i = ch - '0';
        return 0;
    }
    if (ch <= 'f' && ch >= 'a') {
        *i = ch - 'a' + 10;
        return 0;
    }
    if (ch <= 'F' && ch >= 'A') {
        *i = ch - 'A' + 10;
        return 0;
    }
    return -1;
}


char long_to_char(unsigned long i, char *ch)
{
    if (i <= '9' && i >= '0') {
        *ch = i + '0';
        return 0;
    }
    if (i <= 'f' && i >= 'a') {
        *ch = i - 'a' + 10;
        return 0;
    }
    if (i <= 'F' && i >= 'A') {
        *ch = i - 'A' + 10;
        return 0;
    }
    return -1;
}

char string_to_long(char* str, unsigned long *value)
{
    if (strlen(str) == 0) {
        return -1;
    }
    uint64_t sum = 0;
    for (uint64_t i = 0; i < strlen(str); i ++) {
        unsigned long b;
        char_to_long(*(str+i), &b);
        sum += b << ((strlen(str) - 1 - i) * 4);
//        printf("%llx\n",sum);
    }
    *value = sum;
    return 0;
}

unsigned long sub_string_to_long(const char *str, int from,int length)
{
    char sub[length +1];
    strncpy(sub, str + from, length);
    sub[length] = '\0';
    unsigned long result = 0;
    string_to_long(sub, &result);
    return result;
}
