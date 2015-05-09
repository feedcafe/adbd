/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "adb.h"
#include "file_sync_service.h"

typedef struct stinfo stinfo;

struct stinfo {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};

void *service_bootstrap_func(void *x)
{
    stinfo *sti = x;
    sti->func(sti->fd, sti->cookie);
    free(sti);
    return 0;
}

static int create_service_thread(void (*func)(int, void *), void *cookie)
{
    stinfo *sti;
    adb_thread_t t;
    int s[2];

    if(adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return -1;
    }

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = func;
    sti->cookie = cookie;
    sti->fd = s[1];

    if(adb_thread_create( &t, service_bootstrap_func, sti)){
        free(sti);
        adb_close(s[0]);
        adb_close(s[1]);
        printf("cannot create service thread\n");
        return -1;
    }

    D("service thread started, %d:%d\n",s[0], s[1]);
    return s[0];
}

static void init_subproc_child()
{
    setsid();

    // Set OOM score adjustment to prevent killing
    int fd = adb_open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        adb_write(fd, "0", 1);
        adb_close(fd);
    } else {
       D("adb: unable to update oom_score_adj\n");
    }
}

static int create_subproc_pty(const char *cmd, const char *arg0, const char *arg1, pid_t *pid)
{
    D("create_subproc_pty(cmd=%s, arg0=%s, arg1=%s)\n", cmd, arg0, arg1);
    int ptm;

    ptm = unix_open("/dev/ptmx", O_RDWR | O_CLOEXEC); // | O_NOCTTY);
    if(ptm < 0){
        printf("[ cannot open /dev/ptmx - %s ]\n",strerror(errno));
        return -1;
    }

    char devname[64];
    if(grantpt(ptm) || unlockpt(ptm) || ptsname_r(ptm, devname, sizeof(devname)) != 0) {
        printf("[ trouble with /dev/ptmx - %s ]\n", strerror(errno));
        adb_close(ptm);
        return -1;
    }

    *pid = fork();
    if(*pid < 0) {
        printf("- fork failed: %s -\n", strerror(errno));
        adb_close(ptm);
        return -1;
    }

    if (*pid == 0) {
        init_subproc_child();

        int pts = unix_open(devname, O_RDWR | O_CLOEXEC);
        if (pts < 0) {
            fprintf(stderr, "child failed to open pseudo-term slave: %s\n", devname);
            exit(-1);
        }

        dup2(pts, STDIN_FILENO);
        dup2(pts, STDOUT_FILENO);
        dup2(pts, STDERR_FILENO);

        adb_close(pts);
        adb_close(ptm);

        execl(cmd, cmd, arg0, arg1, NULL);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        return ptm;
    }
}

static int create_subproc_raw(const char *cmd, const char *arg0, const char *arg1, pid_t *pid)
{
    D("create_subproc_raw(cmd=%s, arg0=%s, arg1=%s)\n", cmd, arg0, arg1);
    // 0 is parent socket, 1 is child socket
    int sv[2];
    if (unix_socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("[ cannot create socket pair - %s ]\n", strerror(errno));
        return -1;
    }

    *pid = fork();
    if (*pid < 0) {
        printf("- fork failed: %s -\n", strerror(errno));
        adb_close(sv[0]);
        adb_close(sv[1]);
        return -1;
    }

    if (*pid == 0) {
        adb_close(sv[0]);
        init_subproc_child();

        dup2(sv[1], STDIN_FILENO);
        dup2(sv[1], STDOUT_FILENO);
        dup2(sv[1], STDERR_FILENO);

        adb_close(sv[1]);

        execl(cmd, cmd, arg0, arg1, NULL);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        adb_close(sv[1]);
        return sv[0];
    }
}

#define SHELL_COMMAND "/bin/sh"

static void subproc_waiter_service(int fd, void *cookie)
{
    pid_t pid = (pid_t) (uintptr_t) cookie;

    D("entered. fd=%d of pid=%d\n", fd, pid);
    for (;;) {
        int status;
        pid_t p = waitpid(pid, &status, 0);
        if (p == pid) {
            D("fd=%d, post waitpid(pid=%d) status=%04x\n", fd, p, status);
            if (WIFSIGNALED(status)) {
                D("*** Killed by signal %d\n", WTERMSIG(status));
                break;
            } else if (!WIFEXITED(status)) {
                D("*** Didn't exit!!. status %d\n", status);
                break;
            } else if (WEXITSTATUS(status) >= 0) {
                D("*** Exit code %d\n", WEXITSTATUS(status));
                break;
            }
         }
    }
    D("shell exited fd=%d of pid=%d err=%d\n", fd, pid, errno);
    if (SHELL_EXIT_NOTIFY_FD >=0) {
      int res;
      res = writex(SHELL_EXIT_NOTIFY_FD, &fd, sizeof(fd));
      D("notified shell exit via fd=%d for pid=%d res=%d errno=%d\n",
        SHELL_EXIT_NOTIFY_FD, pid, res, errno);
    }
}

static int create_subproc_thread(const char *name, const subproc_mode mode)
{
    stinfo *sti;
    adb_thread_t t;
    int ret_fd;
    pid_t pid = -1;

    const char *arg0, *arg1;
    if (name == 0 || *name == 0) {
        arg0 = "-"; arg1 = 0;
    } else {
        arg0 = "-c"; arg1 = name;
    }

    switch (mode) {
    case SUBPROC_PTY:
        ret_fd = create_subproc_pty(SHELL_COMMAND, arg0, arg1, &pid);
        break;
    case SUBPROC_RAW:
        ret_fd = create_subproc_raw(SHELL_COMMAND, arg0, arg1, &pid);
        break;
    default:
        fprintf(stderr, "invalid subproc_mode %d\n", mode);
        return -1;
    }
    D("create_subproc ret_fd=%d pid=%d\n", ret_fd, pid);

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = subproc_waiter_service;
    sti->cookie = (void*) (uintptr_t) pid;
    sti->fd = ret_fd;

    if (adb_thread_create(&t, service_bootstrap_func, sti)) {
        free(sti);
        adb_close(ret_fd);
        fprintf(stderr, "cannot create service thread\n");
        return -1;
    }

    D("service thread started, fd=%d pid=%d\n", ret_fd, pid);
    return ret_fd;
}

int service_to_fd(const char *name)
{
    int ret = -1;

    if(!strncmp("dev:", name, 4)) {
        ret = unix_open(name + 4, O_RDWR | O_CLOEXEC);
    } else if(!HOST && !strncmp(name, "shell:", 6)) {
        ret = create_subproc_thread(name + 6, SUBPROC_PTY);
    } else if(!HOST && !strncmp(name, "exec:", 5)) {
        ret = create_subproc_thread(name + 5, SUBPROC_RAW);
    } else if(!strncmp(name, "sync:", 5)) {
        ret = create_service_thread(file_sync_service, NULL);
    }
    if (ret >= 0) {
        close_on_exec(ret);
    }
    return ret;
}
