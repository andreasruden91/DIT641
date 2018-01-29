#include "db.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Binary file format:
// 4 byte: number of users
// foreach user:
//     uint32: username length
//     chars:  username (not \0 terminated)
//     uint32: passhash length
//     chars:  passhash (not \0 terminated)
//     uint32: salt length
//     chars:  salt (not \0 terminated)
//     uint32: uid
//     uint32: failed logins
//     uint64: timestamp

static char* read_str(FILE* fp)
{
    int n;
    char* s;
    if (fread(&n, 4, 1, fp) != 1)
        return NULL;
    if ((s = malloc(n+1)) == NULL)
        return NULL;
    if (fread(s, 1, n, fp) != n)
    {
        free(s);
        return NULL;
    }
    s[n] = '\0';
    return s;
}

UserInfoList* db_read_users(void)
{
    FILE* fp;
    UserInfo* user;
    UserInfoList* list;
    uint32_t i, found = 0, num_entries = 0;

    if ((list = malloc(sizeof(UserInfoList))) == NULL)
        return NULL;
    list->size = 0;
    list->head = NULL;
    
    if ((fp = fopen(PASS_DB_PATH, "rb")) == NULL)
        return list;

    if (fread(&num_entries, 4, 1, fp) != 1)
        return list;

    // Read all users from file
    for (i = 0; i < num_entries; ++i)
    {
        if ((user = malloc(sizeof(UserInfo))) == NULL)
            continue;

        // Read all data of user
        if ((user->username = read_str(fp)) == NULL ||
            (user->passhash = read_str(fp)) == NULL ||
            (user->salt = read_str(fp)) == NULL ||
            fread(&user->uid, 4, 1, fp) != 1 ||
            fread(&user->failed_logins, 4, 1, fp) != 1 ||
            fread(&user->timestamp, 8, 1, fp) != 1)
        {
            free(user);
            continue; // Invalid entry, skip
        }

        if (db_list_add(list, user) != 0)
        {
            free(user);
            continue;
        }

        ++found;
    }

    fclose(fp);

    list->size = found;
    return list;
}

void db_write_users(UserInfoList* list)
{
    FILE* fp;
    uint32_t sz;
    UserInfoNode* itr;
    UserInfo* user;

    if ((fp = fopen(PASS_DB_PATH, "wb")) == NULL)
        return;

    fwrite(&list->size, 4, 1, fp);
    itr = list->head;
    while (itr)
    {
        user = itr->user;

        // Username
        sz = strlen(user->username);
        fwrite(&sz, 4, 1, fp);
        fwrite(user->username, 1, sz, fp);

        // Passhash
        sz = strlen(user->passhash);
        fwrite(&sz, 4, 1, fp);
        fwrite(user->passhash, 1, sz, fp);

        // Salt
        sz = strlen(user->salt);
        fwrite(&sz, 4, 1, fp);
        fwrite(user->salt, 1, sz, fp);

        // Uid, failed logins, timestamp
        fwrite(&user->uid, 4, 1, fp);
        fwrite(&user->failed_logins, 4, 1, fp);
        fwrite(&user->timestamp, 8, 1, fp);

        itr = itr->next;
    }

    fclose(fp);
}

int db_list_add(UserInfoList* list, UserInfo* user)
{
    UserInfoNode* node;
    UserInfoNode* itr;

    if ((node = malloc(sizeof(UserInfoNode))) == NULL)
        return -1;

    node->user = user;
    node->next = NULL;

    if (list->head == NULL)
    {
        list->head = node;
    }
    else
    {
        // Add at end of list
        itr = list->head;
        while (itr->next != NULL)
            itr = itr->next;
        itr->next = node;
    }

    ++list->size;

    return 0;
}

void db_list_free(UserInfoList* list)
{
    UserInfoNode* itr = list->head;
    UserInfoNode* tmp;

    while (itr != NULL)
    {
        free(itr->user->username);
        free(itr->user->passhash);
        free(itr->user->salt);
        free(itr->user);
        tmp = itr;
        itr = itr->next;
        free(tmp);
    }

    free(list);
}
