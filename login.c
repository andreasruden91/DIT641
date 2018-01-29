#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include "db.h"
#include "shared.h"

int login_user(char* username, char* password)
{
    UserInfoList* list;
    UserInfoNode* itr;
    char* hash;
    char timebuf[128];
    UserInfo* user = NULL;
    struct tm tmInfo;
    time_t timeTmp;

    list = db_read_users();
    for (itr = list->head; itr != NULL; itr = itr->next)
    {
        if (strcmp(itr->user->username, username) != 0)
            continue;

        // Check if user exceeds failed logins
        if (itr->user->failed_logins >= 5)
        {
            printf("Error: That user is locked. Please contact system administrator.\n");
            break;
        }

        // Test password hash
        hash = passhash(password, itr->user->salt);
        if (strlen(itr->user->passhash) == 43 &&
            strcmp(hash, itr->user->passhash) == 0)
        {
            user = itr->user;
        }
        else
        {
            ++itr->user->failed_logins;
        }

        free(hash);
        break;
    }

    if (user)
    {
        printf("Welcome, %s!\n", user->username);
        if (user->failed_logins > 0)
            printf("Unsuccessful login attempts since last visit: %d\n", user->failed_logins);
        if (time(NULL) - (user->timestamp) > 30*24*60*60)
        {
            timeTmp = (time_t)user->timestamp;
            localtime_r(&timeTmp, &tmInfo);
            if (strftime(timebuf, sizeof(timebuf), "%c", &tmInfo) > 0)
                printf("Your password is old! Last changed %s.\n", timebuf);
        }

        user->failed_logins = 0;
    }
    else
    {
        printf("No such user/password.\n");
    }
    db_write_users(list);
    db_list_free(list);

    // Spawn shell if login successful
    if (user != NULL)
    {
        if (setuid(user->uid) == 0)
        {
            if (system("/bin/sh") == 0)
                return 0;
        }
    }

    return 1;
}

static void signal_handler(int signo)
{
    /* Do Nothing */
}

int main(void)
{
    char* username;
    char* password;
    int login_result;

    // Install signal handling for program interruption
    if (signal(SIGINT, signal_handler) == SIG_ERR ||
        signal(SIGTSTP, signal_handler) == SIG_ERR ||
        signal(SIGQUIT, signal_handler) == SIG_ERR)
    {
        printf("Error: failed to set signal handler\n");
        return 1;
    }

    do
    {
        printf("Login: ");
        if ((username = readline(32)) == NULL)
        {
            printf("Error: Invalid username\n");
            continue;
        }
        if ((password = getpassword()) == NULL)
        {
            printf("Error: Invalid password\n");
            free(username);
            continue;
        }

        login_result = login_user(username, password);

        free(username);
        free(password);
    } while (login_result != 0);
}
