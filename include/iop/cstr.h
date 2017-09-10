/*

 The MIT License (MIT)

 Copyright (c) 2015 BitPay, Inc.
 Copyright (c) 2015 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
*/

#ifndef __LIBIOP_CSTR_H__
#define __LIBIOP_CSTR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "iop.h"

#include <stddef.h>

typedef struct cstring {
    char* str;    /* string data, incl. NUL */
    size_t len;   /* length of string, not including NUL */
    size_t alloc; /* total allocated buffer length */
} cstring;

LIBIOP_API cstring* cstr_new(const char* init_str);
LIBIOP_API cstring* cstr_new_sz(size_t sz);
LIBIOP_API cstring* cstr_new_buf(const void* buf, size_t sz);
LIBIOP_API cstring* cstr_new_cstr(cstring* copy_str);
LIBIOP_API void cstr_free(cstring* s, int free_buf);

LIBIOP_API int cstr_equal(const cstring* a, const cstring* b);
LIBIOP_API int cstr_compare(const cstring* a, const cstring* b);
LIBIOP_API int cstr_resize(cstring* s, size_t sz);
LIBIOP_API int cstr_erase(cstring* s, size_t pos, ssize_t len);

LIBIOP_API int cstr_append_buf(cstring* s, const void* buf, size_t sz);
LIBIOP_API int cstr_append_cstr(cstring* s, cstring* append);

LIBIOP_API int cstr_append_c(cstring* s, char ch);

LIBIOP_API int cstr_alloc_minsize(cstring* s, size_t sz);
#ifdef __cplusplus
}
#endif

#endif /* __LIBLOGDB_CSTR_H__ */
