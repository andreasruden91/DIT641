#ifndef DB__H
#define DB__H

#include <stdint.h>

#define PASS_DB_PATH "/etc/pass.db"

typedef struct
{
    char* username;
    char* passhash;
    char* salt;
    uint32_t uid;
    uint32_t failed_logins;
    uint64_t timestamp; // timestamp of when the password was created/changed
} UserInfo;

typedef struct UserInfoNode_s
{
    UserInfo* user;
    struct UserInfoNode_s* next;
} UserInfoNode;

typedef struct
{
    uint32_t size;
    UserInfoNode* head;
} UserInfoList;

UserInfoList* db_read_users(void);

void db_write_users(UserInfoList* list);

int db_list_add(UserInfoList* list, UserInfo* user);

void db_list_free(UserInfoList* list);

#endif
