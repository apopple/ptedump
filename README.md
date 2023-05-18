# ptedump

## Introduction and Limitations

This is a simple kernel module and userspace to read raw page table
entries and optionally dump page information to the kernel log.

See ptedump_user.c for examples of how to use this.

NOTE: This allows any process including unprivileged processes to dump
any processes page table entries. Therefore usage should be limited to
development environments only as this is insecure.
