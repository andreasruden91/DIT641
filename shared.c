#include "shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <crypt.h>
#include <malloc.h>

char* readline(size_t n)
{
    size_t i = 0;
    int c;
    char* s = 0;

    if ((s = malloc(n)) == NULL)
        return NULL;

    while ((c = getchar()) != EOF && c != '\n')
    {
        if (i+1 < n) // +1 because '\0'
        {
            s[i++] = (char)c;
        }
        else
        {
            free(s);
            return NULL;
        }
    }
    s[i] = '\0';

    return s;
}

char* getpassword(void)
{
    char* password;
    struct termios prev, next;

    if (tcgetattr(fileno(stdin), &prev) != 0)
        return NULL;
    next = prev;
    next.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &next) != 0)
        return NULL;

    printf("Password: ");
    fflush(stdout);

    password = readline(256);
    printf("\n");
    
    tcsetattr(fileno(stdin), TCSAFLUSH, &prev);
    return password;
}

#define SHA256_LEN 43 // base64 encoded
char* passhash(char* password, char* salt)
{
    // FIXME: This is a bad way to store passwords, we should use scrypt.

    char* passhash;
    char* cryptret;
    const int n = 1024;
    char buf[n];
    size_t len;

    if (snprintf(buf, n, "$5$rounds=1000000$%s$", salt) >= n)
        return NULL;
    cryptret = crypt(password, buf);

    // Make sure crypt supports the options and that the result
    // hash is exactly 43 characters
    len = strlen(buf);
    if (strlen(cryptret) != len+SHA256_LEN || strncmp(cryptret, buf, len) != 0)
    {
        free(cryptret);
        return NULL;
    }
    
    if ((passhash = malloc(SHA256_LEN+1)) == NULL)
    {
        free(cryptret);
        return NULL;
    }
    strncpy(passhash, (cryptret+len), SHA256_LEN); // Length of hash checked to be 43 before
    free(cryptret);

    return passhash;
}

char* make_salt(void)
{
    FILE* fp;
    char* res;
    size_t n;

    fp = popen("dd if=/dev/random bs=12 count=1 status=none | base64", "r");
    if (!fp)
        return NULL;

    if ((res = malloc(17)) == NULL)
    {
        fclose(fp);
        return NULL;
    }
    memset(res, '\0', 17);
    n = fread(res, 1, 16, fp);
    fclose(fp);

    if (n != 16)
    {
        free(res);
        return NULL;
    }

    return res;
}
