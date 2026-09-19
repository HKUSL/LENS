## 1) FUSE_INIT - FUSE_HANDLE_KILLPRIV capability negotiation mismatch
**Message:** FUSE_INIT (FI)
**Target Op's path:** fuse_init_out > flags (FUSE_HANDLE_KILLPRIV)
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, a FUSE filesystem is mounted as a privileged (root) deployment — this covers infrastructure FUSE daemons such as virtiofs (QEMU/KVM guest filesystem passthrough), GlusterFS FUSE client (glusterfs-fuse), CephFS FUSE client (ceph-fuse), or FUSE mounts inside containers via /dev/fuse device passthrough. In these deployments, the mount is performed by root and does NOT carry the nosuid restriction that fusermount enforces on non-privileged mounts. The kernel FUSE module (fuse.ko) sends a FUSE_INIT request at mount time, advertising supported capability flags including FUSE_HANDLE_KILLPRIV (bit 19, defined in include/uapi/linux/fuse.h since Linux 4.9) and FUSE_HANDLE_KILLPRIV_V2 (bit 28, since Linux 5.10). The FUSE protocol spec (fuse.h) defines FUSE_HANDLE_KILLPRIV as: "fs handles killing suid/sgid/cap on write/chown/trunc. Suid is killed on write/trunc only if caller did not have CAP_FSETID. Sgid is killed on write/trunc only if caller did not have CAP_FSETID as well as file has group execute permission." When a daemon sets this flag in its fuse_init_out response, the kernel trusts the daemon to fulfill this contract and skips its own kill_priv logic in fuse_file_write_iter() (fs/fuse/file.c).
We assume: (i) the target system runs a privileged FUSE filesystem daemon (root-mounted, no nosuid) as part of its storage infrastructure — this is standard for virtiofs in cloud/VM environments, GlusterFS/CephFS in enterprise storage, and container filesystem passthrough; (ii) the FUSE daemon has a bug or is compromised such that it responds with FUSE_HANDLE_KILLPRIV set in fuse_init_out.flags but does NOT actually clear S_ISUID/S_ISGID bits when handling FUSE_WRITE requests — this constitutes a protocol trust violation at the kernel-daemon boundary; (iii) because the mount is privileged (no nosuid), setuid bits on files within the mount ARE honored by the kernel for execution; (iv) the FUSE mount is accessible to non-root users (common in shared storage scenarios); and (v) the kernel version supports FUSE_HANDLE_KILLPRIV (Linux >= 4.9).
- **Attacker Capability:**
The attacker is a local unprivileged user on the system who can read/write files on the privileged FUSE mount. The attacker does NOT control the daemon — the vulnerability is in the daemon's incorrect implementation of the FUSE_HANDLE_KILLPRIV contract.

**Attack Procedure:**
A privileged FUSE filesystem daemon (e.g., a virtiofs instance, GlusterFS FUSE client, or a custom infrastructure FUSE daemon) negotiates FUSE_HANDLE_KILLPRIV during FUSE_INIT but has a bug in its write handler that fails to clear S_ISUID/S_ISGID bits. This is a realistic scenario because: (a) FUSE_HANDLE_KILLPRIV was added specifically for performance (avoiding an extra round-trip for kill-priv), so daemons are incentivized to claim it; (b) the kill-priv logic involves checking CAP_FSETID of the original caller, group execute bits, and security capabilities — this complexity makes incomplete implementations likely; and (c) the protocol provides no mechanism for the kernel to verify that the daemon actually performed the kill-priv.

The FUSE mount at `/mnt/shared` contains a setuid-root helper binary (e.g., a legitimate administration tool). An unprivileged user writes to this binary (e.g., appending data or modifying a configuration section). The kernel sends FUSE_WRITE to the daemon. The daemon processes the write and stores the data, but due to its bug, does not clear S_ISUID from the file's mode. Under normal kernel behavior without FUSE_HANDLE_KILLPRIV, the kernel would call file_remove_privs() before delegating the write, stripping setuid. But because the daemon negotiated this flag, the kernel trusts the daemon and skips its own check.

After the write, the file retains its setuid-root permission despite having been modified by an unprivileged user. The attacker then executes the modified binary to gain root privileges. The PoC verifies this by: (1) setting up a FUSE daemon that claims FUSE_HANDLE_KILLPRIV but does not implement kill-priv in its write handler, (2) mounting it as root (no nosuid), (3) having an unprivileged user write to a setuid file, (4) confirming via stat() that S_ISUID persists after the write, and (5) demonstrating that execution of the modified binary runs as root.

**Attack Message:**
The following represents the critical FUSE_INIT exchange. The daemon's response is the vulnerability — it asserts a security-critical capability (FUSE_HANDLE_KILLPRIV) that it does not correctly implement. The FUSE protocol provides no verification mechanism, creating a trust gap at the kernel-daemon boundary. This affects privileged FUSE deployments (root-mounted, no nosuid) such as virtiofs, GlusterFS FUSE, and CephFS FUSE.

{
  "fuse_init_request": {
    "opcode": 26,
    "opcode_name": "FUSE_INIT",
    "direction": "kernel_to_daemon",
    "fuse_init_in": {
      "major": 7,
      "minor": 38,
      "max_readahead": 131072,
      "flags": "FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_HANDLE_KILLPRIV | FUSE_HANDLE_KILLPRIV_V2 | ..."
    }
  },
  "fuse_init_response": {
    "opcode": 26,
    "direction": "daemon_to_kernel",
    "fuse_init_out": {
      "major": 7,
      "minor": 38,
      "max_readahead": 131072,
      "flags": "FUSE_HANDLE_KILLPRIV",
      "max_background": 12,
      "congestion_threshold": 9,
      "max_write": 1048576,
      "time_gran": 1
    }
  },
  "exploit_context": {
    "deployment": "privileged FUSE mount (root-mounted, no nosuid): virtiofs, GlusterFS, CephFS, container FUSE passthrough",
    "violation": "daemon claims FUSE_HANDLE_KILLPRIV but does not strip S_ISUID/S_ISGID on FUSE_WRITE",
    "kernel_behavior": "kernel skips file_remove_privs() / kill_priv in fuse_file_write_iter() because flag is negotiated",
    "protocol_gap": "FUSE protocol has no mechanism for kernel to verify daemon actually performs kill-priv",
    "spec_reference": "fuse.h: FUSE_HANDLE_KILLPRIV definition and FUSE_WRITE_KILL_SUIDGID"
  }
}

**Classification:**
ATTACK


## 2) ACCESS - ENOSYS permanent success fallback bypasses permission checks
**Message:** ACCESS (AC)
**Target Op's path:** fuse_access_in > mask
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, a FUSE filesystem is mounted without the `default_permissions` mount option. The FUSE daemon does not implement the access() callback (returns ENOSYS or does not register it). Per the libfuse low-level API documentation (fuse_lowlevel.h), if the access callback is not implemented: "the access(2) system call will return success for every file, for every mask value." The kernel FUSE implementation treats ENOSYS from access as a permanent result — after the first ENOSYS, future access() system calls on this mount return success without consulting the daemon (see fs/fuse/dir.c, FUSE_ACCESS handling).
We assume: (i) the FUSE mount is accessible to multiple users via `allow_other`; (ii) `default_permissions` is NOT set (so the kernel does NOT perform standard Unix permission checks); (iii) the daemon does not implement its own access() callback or intentionally returns ENOSYS; (iv) the daemon serves files with restrictive mode bits (e.g., 0600 owned by root) that should deny access to unprivileged users; and (v) the target system runs Linux >= 2.6.29 where FUSE supports the access opcode.
- **Attacker Capability:**
The attacker is an unprivileged local user who can call access(2) and subsequently open(2)/read(2) on files within the FUSE mount.

**Attack Procedure:**
The attacker targets a FUSE-mounted filesystem at `/mnt/fuse` that serves sensitive files (e.g., `/mnt/fuse/secrets.db`) with mode 0600 owned by root. The mount was created with `allow_other` but without `default_permissions`.

The attacker first calls `access("/mnt/fuse/secrets.db", R_OK)`. The kernel sends a FUSE_ACCESS request to the daemon with fuse_access_in.mask set to R_OK (4). The daemon responds with error = -ENOSYS (errno 38). The kernel interprets this as "access is permanently not implemented" and marks the connection so that all future access() calls return success (error = 0) without consulting the daemon.

From this point on, every access(2) call on any file in this mount succeeds, regardless of the file's mode bits or the caller's UID/GID. The attacker can then open and read `/mnt/fuse/secrets.db` because the kernel never denies access. Without `default_permissions`, there is no fallback permission check in the kernel VFS layer — the daemon was the sole authority, and it abdicated that role via ENOSYS.

The PoC is implemented as a Python script using ctypes to call access(2), then open(2) and read(2) on the target file, verifying that an unprivileged user can read a file that has mode 0600 owned by root on the FUSE mount.

**Attack Message:**
The following represents the FUSE_ACCESS exchange where the daemon's ENOSYS response creates a permanent permission bypass.

{
  "fuse_access_request": {
    "opcode": 34,
    "opcode_name": "FUSE_ACCESS",
    "direction": "kernel_to_daemon",
    "fuse_in_header": {
      "nodeid": 2,
      "uid": 1000,
      "gid": 1000,
      "pid": 12345
    },
    "fuse_access_in": {
      "mask": 4,
      "mask_symbolic": "R_OK"
    }
  },
  "fuse_access_response": {
    "direction": "daemon_to_kernel",
    "fuse_out_header": {
      "error": -38,
      "error_name": "ENOSYS"
    }
  },
  "exploit_context": {
    "kernel_behavior": "ENOSYS treated as permanent success for all future access() calls on this mount",
    "mount_options": ["allow_other"],
    "missing_options": ["default_permissions"],
    "effect": "unprivileged user passes all access checks on all files in mount"
  }
}

**Classification:**
ATTACK


## 3) IOCTL - cmd field truncation from 64-bit to 32-bit
**Message:** IOCTL (IO)
**Target Op's path:** fuse_ioctl_in > cmd
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, a FUSE filesystem implements the ioctl callback to expose device-like control interfaces. The FUSE daemon dispatches ioctl handling based on the `cmd` field in fuse_ioctl_in. Per the libfuse documentation (fuse_lowlevel.h): "Note: the unsigned long request (cmd) will get truncated to 32 bit." This is because the FUSE kernel protocol defines fuse_ioctl_in.cmd as __u32 (see include/uapi/linux/fuse.h), but the ioctl(2) system call and the C ioctl interface use unsigned long for the request number (64-bit on LP64 systems).
We assume: (i) the FUSE daemon handles multiple ioctl commands and dispatches them via a switch/map on the cmd value; (ii) some application constructs ioctl request numbers using _IOC() macros that produce values where the upper 32 bits carry type/direction/size encoding; (iii) two different ioctl commands exist whose lower 32 bits collide after truncation; (iv) the daemon does not validate that the received cmd matches the expected full 64-bit value; and (v) one of the colliding commands is privileged (e.g., device reset, firmware flash) while the other is unprivileged (e.g., status query).
- **Attacker Capability:**
The attacker is a local user who can open files on the FUSE mount and issue ioctl(2) system calls.

**Attack Procedure:**
The FUSE daemon serves a virtual device file `/mnt/fuse/control` that supports two ioctl commands: (a) SAFE_STATUS_QUERY with full 64-bit cmd = 0x0000000080046601, which returns device status (unprivileged, read-only); and (b) PRIVILEGED_RESET with full 64-bit cmd = 0xC004000046601, which performs a device reset (privileged, destructive).

When the attacker issues ioctl(fd, 0xC004000046601, &arg) from userspace, the kernel's FUSE ioctl path packs the request into fuse_ioctl_in where cmd is a __u32 field. The value 0xC004000046601 is truncated to its lower 32 bits: 0x00046601. Meanwhile, the SAFE_STATUS_QUERY command 0x80046601 also truncates to 0x00046601 (same lower 32 bits).

The daemon receives cmd = 0x00046601 for both requests and cannot distinguish them. If the daemon's dispatch logic maps 0x00046601 to the status query handler (the expected common case), the attacker's intended privileged reset is silently converted to a safe query — a different security issue (silent failure). If the dispatch maps to the reset handler, the attacker triggers a privileged operation by issuing an ioctl that appears to be a status query at the userspace API level.

The PoC creates a minimal FUSE daemon with two ioctl handlers whose full cmd values differ only in the upper 32 bits, demonstrates that both arrive at the daemon with the same truncated cmd, and shows that the wrong handler is dispatched.

**Attack Message:**
The following represents the FUSE_IOCTL exchange showing the truncation of the cmd field.

{
  "fuse_ioctl_request": {
    "opcode": 39,
    "opcode_name": "FUSE_IOCTL",
    "direction": "kernel_to_daemon",
    "fuse_in_header": {
      "nodeid": 5,
      "uid": 1000,
      "gid": 1000,
      "pid": 54321
    },
    "fuse_ioctl_in": {
      "fh": 1,
      "flags": 0,
      "cmd_intended_userspace": "0xC004000046601 (unsigned long, 64-bit)",
      "cmd_received_daemon": "0x00046601 (__u32, truncated to 32-bit)",
      "in_size": 0,
      "out_size": 256
    }
  },
  "exploit_context": {
    "truncation": "FUSE protocol fuse_ioctl_in.cmd is __u32, truncates unsigned long from userspace ioctl(2)",
    "collision": "0xC004000046601 (privileged reset) and 0x80046601 (status query) both truncate to 0x00046601",
    "reference": "libfuse fuse_lowlevel.h ioctl callback documentation"
  }
}

**Classification:**
ATTACK


## 4) MOUNT - allow_other without default_permissions enables confused deputy attack
**Message:** MOUNT (MT)
**Target Op's path:** mount_options > allow_other
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, an unprivileged user has mounted a FUSE filesystem using fusermount3 with the `allow_other` option (enabled via /etc/fuse.conf `user_allow_other`). The `default_permissions` option is NOT set. Per the kernel FUSE documentation (Documentation/filesystems/fuse.rst), the security goals for non-privileged mounts include: "the mount owner shouldn't be able to get elevated privileges through the filesystem" and "the mount owner shouldn't be able to induce undesired behavior in other users' or the superuser's processes." However, these goals rely on proper mount option configuration.
We assume: (i) the attacker is the mount owner running a malicious FUSE daemon; (ii) `allow_other` is set, permitting root and other users to access the mount (kernel docs: "This option overrides the measure which restricts file access to the user mounting the filesystem"); (iii) `default_permissions` is NOT set, so the kernel does NOT perform standard Unix permission checks — the daemon is solely responsible for access control; (iv) root or a privileged process traverses the FUSE mount as part of normal operation (e.g., a cron job, backup tool, or antivirus scanner walks the filesystem tree); and (v) fusermount3 enforces nosuid and nodev, but these do not prevent the confused deputy attack described below.
- **Attacker Capability:**
The attacker controls the FUSE daemon and thus controls all file metadata and content returned to any process accessing the mount.

**Attack Procedure:**
The attacker mounts a malicious FUSE filesystem at `/home/attacker/share` with `allow_other` (no `default_permissions`). The daemon implements the following behavior: for any process with uid != 0 (including the attacker), it serves an innocuous directory listing. For processes with uid == 0 (root), it serves a carefully crafted filesystem tree.

When a root-owned backup tool (e.g., rsync running as root for system backup) traverses `/home/attacker/share`, the daemon detects uid=0 in fuse_in_header.uid and serves a malicious directory structure: (a) a symlink `/home/attacker/share/.config` -> `/etc/shadow` which the backup tool follows, causing it to copy /etc/shadow to the attacker's backup destination; or (b) a file named `authorized_keys` with attacker-controlled content, paired with a path structure that the backup tool copies into `/root/.ssh/authorized_keys`; or (c) a world-writable directory that tricks the root process into creating files in locations the attacker can predict.

The daemon uses fuse_in_header.uid (available in every FUSE request) to distinguish between the attacker (uid 1000) and the victim root process (uid 0), serving different filesystem views to each. Without `default_permissions`, the kernel does not check whether uid 0 actually has permission per standard Unix semantics — it forwards every request to the daemon, which approves everything.

The PoC is implemented as a Python libfuse daemon that demonstrates UID-based content differentiation and is tested with a root-owned rsync backup traversal.

**Attack Message:**
The following represents the mount configuration that enables the confused deputy attack, plus an example FUSE_LOOKUP exchange showing UID-dependent responses.

{
  "fuse_mount_configuration": {
    "mount_point": "/home/attacker/share",
    "mount_options": ["allow_other", "nosuid", "nodev"],
    "missing_options": ["default_permissions"],
    "mount_owner_uid": 1000
  },
  "fuse_lookup_example": {
    "opcode": 1,
    "opcode_name": "FUSE_LOOKUP",
    "request_from_root": {
      "fuse_in_header": {
        "uid": 0,
        "gid": 0,
        "pid": 9876,
        "nodeid": 1
      },
      "name": ".config"
    },
    "daemon_response_to_root": {
      "entry_out": {
        "nodeid": 100,
        "attr": {
          "mode": "0120777 (symlink)",
          "symlink_target": "/etc/shadow"
        }
      }
    },
    "daemon_response_to_attacker": {
      "entry_out": {
        "nodeid": 100,
        "attr": {
          "mode": "040755 (directory)",
          "content": "innocuous files"
        }
      }
    }
  }
}

**Classification:**
ATTACK


## 5) FUSE_GETATTR - normal file attribute retrieval
**Message:** FUSE_GETATTR (GA)
**Target Op's path:** fuse_getattr_in > getattr_flags
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, a FUSE filesystem (e.g., sshfs, rclone mount, or s3fs) is mounted and a user calls stat(2) on a file within the mount, triggering a FUSE_GETATTR request. The daemon implements the getattr callback and returns standard struct stat fields (st_mode, st_size, st_uid, st_gid, st_mtime, etc.).
We assume: (i) the FUSE mount has default mount options (no allow_other, default_permissions not relevant for read-only metadata); (ii) the user has standard access to the mount point; (iii) the daemon correctly implements getattr; and (iv) the kernel caches attribute results per the attr_valid/attr_valid_nsec timeout returned by the daemon.
- **Attacker Capability:**
The attacker is restricted to calling stat(2) on files within the FUSE mount and observing the returned struct stat.

**Attack Procedure:**
The user runs `stat /mnt/fuse/document.txt` or an equivalent system call. The kernel sends a FUSE_GETATTR request (opcode 3) to the daemon with fuse_in_header.nodeid set to the inode number of document.txt. The getattr_flags field may include FUSE_GETATTR_FH if a file handle is available. The daemon reads the underlying storage metadata and replies with fuse_attr_out containing the file attributes and a cache validity timeout.

The kernel receives the response and populates the struct stat returned to the user's stat(2) call. This is a purely informational, read-only operation. The returned attributes (size, timestamps, permissions) are the same information available via `ls -l`. No filesystem state is modified, no privileged information is disclosed beyond what the file's own metadata contains, and no security boundary is crossed. The operation is equivalent to stat(2) on any local filesystem.

**Attack Message:**
The following is the FUSE_GETATTR exchange represented in a fixed JSON structure.

{
  "fuse_getattr_request": {
    "opcode": 3,
    "opcode_name": "FUSE_GETATTR",
    "direction": "kernel_to_daemon",
    "fuse_in_header": {
      "nodeid": 42,
      "uid": 1000,
      "gid": 1000,
      "pid": 11111
    },
    "fuse_getattr_in": {
      "getattr_flags": 0,
      "fh": 0
    }
  },
  "fuse_getattr_response": {
    "direction": "daemon_to_kernel",
    "fuse_attr_out": {
      "attr_valid": 1,
      "attr": {
        "ino": 42,
        "size": 4096,
        "mode": "0100644 (regular file, rw-r--r--)",
        "uid": 1000,
        "gid": 1000
      }
    }
  }
}

**Classification:**
SAFE


## 6) FUSE_READ - normal file content read within permissions
**Message:** FUSE_READ (RD)
**Target Op's path:** fuse_read_in > offset
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, a FUSE filesystem is mounted and a user reads a file they own within the mount. The user has read permission on the file. The daemon implements the read callback which fetches data from the underlying storage and returns it to the kernel.
We assume: (i) the FUSE mount uses default permissions or the daemon correctly enforces access control; (ii) the file being read is owned by the requesting user with mode 0644 or more permissive; (iii) the read offset and size are within the file's bounds; and (iv) the daemon correctly handles the FUSE_READ request.
- **Attacker Capability:**
The attacker is restricted to calling read(2) on a file descriptor obtained via open(2) on a file within the FUSE mount.

**Attack Procedure:**
The user opens `/mnt/fuse/readme.txt` (a file they own) and calls read(2) requesting 4096 bytes from offset 0. The kernel sends a FUSE_READ request (opcode 15) to the daemon with fuse_read_in containing the file handle (fh), offset (0), and size (4096). The daemon reads the first 4096 bytes of the file from its backing store and replies with the data.

The kernel passes the data back to the user's read(2) call. This is a standard file read operation. The user is reading their own file with proper permissions. No sensitive data beyond what the user already has access to is disclosed. No state is modified. The operation is equivalent to read(2) on any local filesystem.

**Attack Message:**
The following is the FUSE_READ exchange represented in a fixed JSON structure.

{
  "fuse_read_request": {
    "opcode": 15,
    "opcode_name": "FUSE_READ",
    "direction": "kernel_to_daemon",
    "fuse_in_header": {
      "nodeid": 42,
      "uid": 1000,
      "gid": 1000,
      "pid": 22222
    },
    "fuse_read_in": {
      "fh": 3,
      "offset": 0,
      "size": 4096,
      "read_flags": 0,
      "lock_owner": 0,
      "flags": "O_RDONLY"
    }
  },
  "fuse_read_response": {
    "direction": "daemon_to_kernel",
    "fuse_out_header": {
      "error": 0
    },
    "data": "<4096 bytes of file content>"
  }
}

**Classification:**
SAFE


## 7) FUSE_STATFS - filesystem statistics query
**Message:** FUSE_STATFS (SF)
**Target Op's path:** fuse_statfs_out > st
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, a FUSE filesystem is mounted and a user calls statfs(2) on the mount point, triggering a FUSE_STATFS request. The daemon responds with filesystem-level statistics (total blocks, free blocks, available blocks, total inodes, etc.).
We assume: (i) the user has standard access to the mount point; (ii) the daemon correctly implements statfs; (iii) the statistics reflect the underlying storage capacity; and (iv) the mount uses default options.
- **Attacker Capability:**
The attacker is restricted to calling statfs(2) on the FUSE mount point and observing the returned struct statvfs.

**Attack Procedure:**
The user runs `df /mnt/fuse` or calls statfs(2) on the mount point. The kernel sends a FUSE_STATFS request (opcode 17) to the daemon. The daemon gathers filesystem statistics from its backing store and replies with fuse_statfs_out containing fuse_kstatfs (blocks, bfree, bavail, files, ffree, bsize, namelen, frsize).

The kernel returns this information to the user's statfs(2) call. This is a read-only, informational operation. The returned statistics are equivalent to what `df` shows for any filesystem. No per-file data is disclosed, no state is modified, and no security boundary is crossed. The total/free space information is not considered sensitive.

**Attack Message:**
The following is the FUSE_STATFS exchange represented in a fixed JSON structure.

{
  "fuse_statfs_request": {
    "opcode": 17,
    "opcode_name": "FUSE_STATFS",
    "direction": "kernel_to_daemon",
    "fuse_in_header": {
      "nodeid": 1,
      "uid": 1000,
      "gid": 1000,
      "pid": 33333
    }
  },
  "fuse_statfs_response": {
    "direction": "daemon_to_kernel",
    "fuse_statfs_out": {
      "st": {
        "blocks": 1048576,
        "bfree": 524288,
        "bavail": 524288,
        "files": 65536,
        "ffree": 32768,
        "bsize": 4096,
        "namelen": 255,
        "frsize": 4096
      }
    }
  }
}

**Classification:**
SAFE


## 8) FUSE_LOOKUP - normal file name lookup
**Message:** FUSE_LOOKUP (LK)
**Target Op's path:** fuse_entry_out > nodeid
**Threat Model:**
- **Attack Assumption:**
On the target Linux system, a FUSE filesystem is mounted and a user accesses a file by name (e.g., open("/mnt/fuse/report.pdf")), triggering a FUSE_LOOKUP request. The daemon resolves the name to an inode and returns entry attributes.
We assume: (i) the user has permission to access the parent directory; (ii) the file exists in the FUSE filesystem; (iii) the daemon correctly implements lookup; and (iv) the mount uses default options.
- **Attacker Capability:**
The attacker is restricted to accessing files by path within the FUSE mount.

**Attack Procedure:**
The user accesses `/mnt/fuse/report.pdf`. The kernel sends a FUSE_LOOKUP request (opcode 1) to the daemon with the parent directory's nodeid and the filename "report.pdf". The daemon looks up the file in its backing store and replies with fuse_entry_out containing the file's nodeid, generation, entry_valid timeout, attr_valid timeout, and the file's attributes (fuse_attr).

The kernel caches the lookup result for the specified validity period and returns the resolved inode to the VFS layer. This is a standard name resolution operation, equivalent to the dcache lookup on local filesystems. No sensitive information is disclosed beyond the file's existence and metadata. No state is modified. The lookup count mechanism (nlookup) is internal bookkeeping between kernel and daemon for inode lifetime management.

**Attack Message:**
The following is the FUSE_LOOKUP exchange represented in a fixed JSON structure.

{
  "fuse_lookup_request": {
    "opcode": 1,
    "opcode_name": "FUSE_LOOKUP",
    "direction": "kernel_to_daemon",
    "fuse_in_header": {
      "nodeid": 1,
      "uid": 1000,
      "gid": 1000,
      "pid": 44444
    },
    "name": "report.pdf"
  },
  "fuse_lookup_response": {
    "direction": "daemon_to_kernel",
    "fuse_entry_out": {
      "nodeid": 55,
      "generation": 1,
      "entry_valid": 1,
      "attr_valid": 1,
      "attr": {
        "ino": 55,
        "size": 1048576,
        "mode": "0100644 (regular file, rw-r--r--)",
        "uid": 1000,
        "gid": 1000
      }
    }
  }
}

**Classification:**
SAFE
