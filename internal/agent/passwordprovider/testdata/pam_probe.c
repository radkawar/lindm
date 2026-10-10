/* Native qualification only. Never installed by the agent package.
 * Compile against the guest's libpam, install root-owned mode 4755 in the
 * disposable guest, and execute with real UID lindm-pam-test. No other account
 * or PAM service can be selected. Secret answers arrive through private stdin.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define FIXTURE_USER "lindm-pam-test"
#define FIXTURE_SERVICE "lindm-password-qualification"
#define ANSWERS 8
#define ANSWER_BYTES 1024

static int responses_used;

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **out, void *unused) {
    (void)unused;
    if (count <= 0 || count > ANSWERS) return PAM_CONV_ERR;
    struct pam_response *responses = calloc((size_t)count, sizeof(*responses));
    if (responses == NULL) return PAM_BUF_ERR;
    for (int i = 0; i < count; ++i) {
        int style = messages[i]->msg_style;
        if (style == PAM_TEXT_INFO || style == PAM_ERROR_MSG) continue;
        if (style == PAM_PROMPT_ECHO_ON) {
            responses[i].resp = strdup(FIXTURE_USER);
            if (responses[i].resp == NULL) goto fail;
            continue;
        }
        if (style != PAM_PROMPT_ECHO_OFF || responses_used++ >= ANSWERS) goto fail;
        char answer[ANSWER_BYTES + 2];
        if (fgets(answer, sizeof(answer), stdin) == NULL) goto fail;
        size_t length = strlen(answer);
        if (length == 0 || answer[length - 1] != '\n') {
            explicit_bzero(answer, sizeof(answer));
            goto fail;
        }
        answer[--length] = '\0';
        responses[i].resp = strdup(answer);
        explicit_bzero(answer, sizeof(answer));
        if (responses[i].resp == NULL) goto fail;
    }
    *out = responses;
    return PAM_SUCCESS;
fail:
    for (int i = 0; i < count; ++i) {
        if (responses[i].resp != NULL) {
            explicit_bzero(responses[i].resp, strlen(responses[i].resp));
            free(responses[i].resp);
        }
    }
    free(responses);
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "authenticate") != 0 &&
                      strcmp(argv[1], "password") != 0)) return 64;
    /* Refuse root and all real owner accounts before opening PAM. */
    uid_t real_uid = getuid();
    if (real_uid == 0 || geteuid() != 0 || real_uid < 1000) return 77;
    FILE *accounts = fopen("/etc/passwd", "re");
    if (accounts == NULL) return 77;
    int bound = 0;
    struct passwd *entry;
    while ((entry = fgetpwent(accounts)) != NULL) {
        if (strcmp(entry->pw_name, FIXTURE_USER) == 0 && entry->pw_uid == real_uid)
            bound = 1;
        else if (entry->pw_uid == real_uid) {
            bound = 0;
            break;
        }
    }
    int read_failed = ferror(accounts);
    if (fclose(accounts) != 0 || read_failed || !bound) return 77;
    if (prctl(PR_SET_DUMPABLE, 0) != 0) return 77;
    if (clearenv() != 0 || setenv("LANG", "C", 1) != 0 ||
        setenv("PATH", "/usr/sbin:/usr/bin", 1) != 0) return 77;
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *handle = NULL;
    int status = pam_start(FIXTURE_SERVICE, FIXTURE_USER, &conv, &handle);
    if (status != PAM_SUCCESS) return 70;
    if (strcmp(argv[1], "password") == 0) {
        status = pam_chauthtok(handle, 0);
    } else {
        status = pam_authenticate(handle, 0);
        if (status == PAM_SUCCESS) status = pam_acct_mgmt(handle, 0);
    }
    int ended = pam_end(handle, status);
    /* No prompts, usernames, password tokens or shadow material are recorded. */
    if (printf("pam_result=%d\n", status) < 0 || fflush(stdout) != 0) return 74;
    if (ended != PAM_SUCCESS) return 70;
    return status == PAM_SUCCESS ? 0 : 1;
}
