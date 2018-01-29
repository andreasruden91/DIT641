#ifndef SHARD_H
#define SHARED_H

#include <stddef.h>

char* readline(size_t n);

char* getpassword(void);

// Parameters:
// salt: should be a base64 encoded up-to 16 characters null terminated string
// Returns:
// A base64-encoded hash (43 characters) or NULL on failure
char* passhash(char* password, char* salt);

// Get 16 bytes from /dev/urandom
char* make_salt(void);

#endif
