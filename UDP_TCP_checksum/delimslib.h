//
//  delimslib.h
//  UDP_TCP_checksum
//
//  Created by delims on 2019/12/25.
//  Copyright © 2019 delims. All rights reserved.
//

#ifndef delimslib_h
#define delimslib_h

#include <stdio.h>

char char_to_long(char ch, unsigned long *i);
char long_to_char(unsigned long i, char *ch);

char string_to_long(char* str, unsigned long *value);

unsigned long sub_string_to_long(const char *str, int from,int length);


#endif /* delimslib_h */
