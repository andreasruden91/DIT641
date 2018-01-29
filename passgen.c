#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include "shared.h"
#include "db.h"

int main(void)
{
    char* username = NULL;
    char* password = NULL;
    char* hash = NULL;
    char* salt = NULL;
    UserInfoList* list;
    UserInfoNode* itr;
    UserInfo* user;
    uint32_t uid = 1;

    printf("Current users:\n");
    if ((list = db_read_users()) == NULL)
        return -1;
    itr = list->head;
    while (itr)
    {
        user = itr->user;
        printf("username:%s, passhash:%s, salt:%s, uid:%d, failed:%d, time:%lu\n",
            user->username, user->passhash, user->salt,
            user->uid, user->failed_logins, user->timestamp);
        if (user->uid >= uid)
            uid = user->uid + 1;
        itr = itr->next;
    }

    user = malloc(sizeof(UserInfo));

    printf("Login: ");
    if ((username = readline(32)) == NULL)
    {
        printf("Error: Invalid username\n");
        return -10; // Leaks, but w/e, we're exiting anyway
    }
    if ((password = getpassword()) == NULL)
    {
        printf("Error: Invalid password\n");
        return -20; // Leaks, but w/e, we're exiting anyway
    }

    salt = make_salt();
    if (!salt)
    {
        printf("Error: Could not generate salt\n");
        return -1; // Leaks, but w/e, we're exiting anyway
    }
    hash = passhash(password, salt);
    if (!hash)
    {
        printf("Error: Could not make hash\n");
        return -1; // Leaks, but w/e, we're exiting anyway
    }

    user->username = username;
    user->passhash = hash;
    user->salt = salt;
    user->uid = uid;
    user->failed_logins = 0;
    user->timestamp = time(NULL);

    db_list_add(list, user);
    db_write_users(list);
    db_list_free(list);

    return (hash != NULL) ? 0 : -1;
}
