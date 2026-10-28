/* Generated-file API regression; never runs with elevated privileges. */
#define _GNU_SOURCE
#include <sys/acl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void require(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "ACL API regression failed: %s (errno=%d)\n", operation, errno);
        exit(1);
    }
}

static int refused_link(void) {
    return errno == ELOOP || errno == EOPNOTSUPP || errno == ENOTSUP;
}

int main(int argc, char **argv) {
    require(argc == 2 && getuid() != 0 && geteuid() != 0, "unprivileged invocation");
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(directory >= 0, "open generated directory");
    acl_t access = acl_get_file_at(directory, "payload", AT_SYMLINK_NOFOLLOW, ACL_TYPE_ACCESS);
    require(access != NULL && acl_valid(access) == 0, "read access ACL without following links");
    require(acl_set_file_at(directory, "payload", AT_SYMLINK_NOFOLLOW, ACL_TYPE_ACCESS, access) == 0,
            "set access ACL on regular file");
    acl_t defaults = acl_get_file_at(directory, "directory", AT_SYMLINK_NOFOLLOW, ACL_TYPE_DEFAULT);
    acl_entry_t entry;
    require(defaults != NULL && acl_valid(defaults) == 0 && acl_get_entry(defaults, ACL_FIRST_ENTRY, &entry) == 1,
            "read nonempty default ACL");
    errno = 0;
    acl_t linked = acl_get_file_at(directory, "link", AT_SYMLINK_NOFOLLOW, ACL_TYPE_ACCESS);
    require(linked == NULL && refused_link(), "reject access ACL read through final symlink");
    errno = 0;
    require(acl_set_file_at(directory, "link", AT_SYMLINK_NOFOLLOW, ACL_TYPE_ACCESS, access) == -1 && refused_link(),
            "reject access ACL write through final symlink");
    /* Compatibility is explicit: callers using flags=0 still follow links. */
    acl_t legacy = acl_get_file_at(directory, "link", 0, ACL_TYPE_ACCESS);
    require(legacy != NULL, "legacy symlink-following behavior remains visible");
    acl_free(legacy);
    acl_free(defaults);
    acl_free(access);
    close(directory);
    puts("{\"accessRead\":true,\"accessWrite\":true,\"defaultRead\":true,"
         "\"noFollowReadRejected\":true,\"noFollowWriteRejected\":true,\"legacyStillFollows\":true}");
    return 0;
}
