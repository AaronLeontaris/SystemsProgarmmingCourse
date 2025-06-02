#include "parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

//helper function
static int run_command(struct command *cmd, int input_fd, int output_fd, int is_last, int is_background, pid_t *child_pid) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        // cild process for input reditrection
        if (cmd->input_redir) {
            int fd = open(cmd->input_redir, O_RDONLY);
            if (fd < 0) {
                perror("open input_redir");
                exit(1);
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
        } else if (input_fd != STDIN_FILENO) {
            dup2(input_fd, STDIN_FILENO);
        }
        // output redircet
        if (cmd->output_redir) {
            int fd = open(cmd->output_redir, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd < 0) {
                perror("open output_redir");
                exit(1);
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
        } else if (output_fd != STDOUT_FILENO) {
            dup2(output_fd, STDOUT_FILENO);
        }
        // shuttin down unused
        if (input_fd != STDIN_FILENO) close(input_fd);
        if (output_fd != STDOUT_FILENO) close(output_fd);

        execvp(cmd->argv[0], cmd->argv);
        perror("execvp");
        exit(127);
    } else {
        //parent process
        if (child_pid) *child_pid = pid;
        return 0;
    }
}

int run_pipeline(struct pipeline *pl) {
    if (!pl || !pl->first_command) return -1;
    struct command *cmd = pl->first_command;
    int ncmd = 0;
    for (struct command *c = cmd; c; c = c->next) ncmd++;

    int prev_fd = -1; //precious pipe
    int status = 0;
    pid_t *pids = calloc(ncmd, sizeof(pid_t));
    if (!pids) {
        perror("calloc");
        return -1;
    }
    int i = 0;
    while (cmd) {
        int pipefd[2] = {-1, -1};
        int is_last = cmd->next == NULL;
        if (!is_last) {
            if (pipe(pipefd) < 0) {
                perror("pipe");
                free(pids);
                return -1;
            }
        }
        int input_fd = prev_fd == -1 ? STDIN_FILENO : prev_fd;
        int output_fd = is_last ? STDOUT_FILENO : pipefd[1];

        // ausführende s commands
        if (run_command(cmd, input_fd, output_fd, is_last, pl->background, &pids[i]) != 0) {
            if (!is_last) { close(pipefd[0]); close(pipefd[1]); }
            free(pids);
            return -1;
        }

        //closing outputfd in parent
        if (!is_last) close(pipefd[1]);
        if (input_fd != STDIN_FILENO) close(input_fd);

        prev_fd = is_last ? -1 : pipefd[0];
        cmd = cmd->next;
        i++;
    }
    // waiting fpr child
    int rc = 0;
    if (!pl->background) {
        for (int j = 0; j < ncmd; ++j) {
            int wstatus = 0;
            if (waitpid(pids[j], &wstatus, 0) < 0) {
                perror("waitpid");
                rc = -1;
            }
        }
    }
    free(pids);
    return rc;
}

int run_builtin(enum builtin_type type, char *builtin_arg) {
    switch(type) {
        case BUILTIN_WAIT: {
            if (builtin_arg) {
                char *endptr;
                pid_t pid = (pid_t)strtol(builtin_arg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "wait: invalid PID argument  \n");
                    return 1;
                }
                if (waitpid(pid, NULL, 0) < 0) {
                    perror("waitpid");
                    return 1;
                }
            } else {
                if (waitpid(-1, NULL, 0) < 0) {
                    perror("waitpid");
                    return 1;
                }
            }
            break;
        }
        case BUILTIN_EXIT: {
            int code = 0; // default
            if (builtin_arg) {
                char *endptr;
                code = (int)strtol(builtin_arg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "exit:invalid exit code\n");
                    code = 1;
                }
            }
            exit(code);
            // not reached
        }
        case BUILTIN_KILL: {
            if (!builtin_arg) {
                fprintf(stderr,"kill: missing PID argument\n");
                return 1;
            }
            char *endptr;
            pid_t pid = (pid_t)strtol(builtin_arg, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "kill: invalid PID argument\n");
                return 1;
            }
            if (kill(pid, SIGTERM) < 0) {
                perror("kill");
                return 1;
            }
            break;
        }
        default:
            fprintf(stderr, "Unknown builtin\n");
            return 1;
    }
    return 0;
}
