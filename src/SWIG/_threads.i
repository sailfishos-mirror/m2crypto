/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <pythread.h>
#include <openssl/crypto.h>

void threading_locking_callback(int mode, int type, const char *file, int line) {
}

unsigned long threading_id_callback(void) {
    return (unsigned long)PyThread_get_thread_ident();
}
%}

%inline %{
void threading_init(void) {
}

void threading_cleanup(void) {
}
%}

