# SELinux namespaces with policy-local object labels

## Status

This document defines the policy-local label architecture which supersedes the
sealed label-map design.  The map/view implementation has been removed; the
remaining migration gates track userspace conversion and validation of this
model.

## Security model

SELinux policy namespaces form a rooted tree.  A task in a leaf is authorized
by exactly the policies on the path from the initial namespace to that leaf.
Sibling policies never participate in an ordinary operation.

```text
                 H
              /  |  \
             A   B   C
             |   |   |
             D   E   F

task in D: H -> A -> D
task in E: H -> B -> E
task in F: H -> C -> F
```

Every policy on the path makes an independent AVC decision.  A child can add
restrictions but cannot suppress an ancestor decision, mutate an ancestor's
label, or install policy into an ancestor.  Namespace administration is
authorized in the user namespace which owns the SELinux policy namespace; it
never grants authority over the initial SELinux namespace.

## Object identity and local labels

A kernel object has one non-reused SELinux object identity.  Every SELinux
state owns a side table keyed by that identity.  A table entry contains only
the label understood by that state:

```text
object identity 4711

H.object_labels[4711] = system_u:object_r:device_t:s0
A.object_labels[4711] = u:object_r:device:s0
D.object_labels[4711] = u:object_r:container_device:s0
```

There is no parent-to-child or child-to-parent translation.  Equal context
strings in different policies are not assumed to have equal meaning.  A
missing local entry is interpreted by that policy as its own initial
`unlabeled` SID; it is not an error in a translation layer.  The policy may
deny that label, permit it temporarily, or replace the local entry through an
authorized relabel operation.

An entry is replaced atomically and is never modified in place while visible
to RCU readers.  Object IDs saturate instead of wrapping.  Tables and entries
are quota-accounted to their owner user namespace.

## Persistent filesystem labels

The on-disk `security.selinux` xattr stores one policy's persistent
representation.  The filesystem records which SELinux state owns that
persistent representation.  This ownership controls xattr encoding and
writeback only; it does not select which policies authorize an operation.

When a state first observes an inode, it independently resolves the physical
xattr using its own policy and publishes that result in its side table.  Equal
bytes may therefore resolve to different local SIDs.  A context unknown to one
policy retains the ordinary SELinux unmapped-context behavior: AVC decisions
for that state treat it as that state's `unlabeled` SID, and a later policy
reload may map it without changing the physical xattr.

An authorized `setxattr`, `restorecon`, transition, or creation operation
publishes policy-local entries for every policy involved in that operation.
Only the persistent owner may replace the physical xattr bytes; other states
may replace only their side-table entries.  The VFS exposes this local-only
relabel as an LSM xattr override after ordinary stacked-LSM permission checks
and delegation breaking, so the physical filesystem is never presented with
an xattr write owned by another policy.

A superblock may predate a descendant policy.  On first observation by such a
policy, SELinux lazily resolves that policy's `fs_use`, filesystem, default,
mountpoint, creator, and root labels and publishes them as one local
transaction.  This does not remount the filesystem, replay mount options, or
change its persistent-label owner.

Consequently a shared inode can have independent host and Android labels
without cloning the filesystem and without making mount topology part of
label identity.

## Creation and relabel

Creation is one transaction over the credential ancestry.  For every state in
the root-to-leaf path the kernel uses that state's subject label and parent
directory label to compute the new object label.  It authorizes the create,
transition, and filesystem association in every state before publishing any
entry.  Failure rolls back the complete set.

Relabel follows the same rule.  Each state independently authorizes
`relabelfrom`, `relabelto`, transition, and association.  A child can replace
only its local label unless it also has explicit authority in every ancestor
whose persistent representation would change.

## Policy reload and open files

Every state retains its own policy sequence and AVC.  Reloading a state bumps
the chain epoch for that state and its descendants.  Existing file
descriptions retain the object identity and opener credential chain, not a
translated SID.  The next `read`, `write`, `mmap`, `ioctl`, `fcntl`, async
operation, or transfer re-resolves the local labels and revalidates the full
chain when its cached epoch is stale.

Reload scope is hierarchical:

```text
reload H -> invalidates H and every descendant
reload A -> invalidates A and D
reload D -> invalidates D only
```

## Pathless objects

Sockets, SysV IPC, POSIX message queues, keys, BPF objects, perf events,
Binder objects, XFRM state, network assertions, io_uring requests, and other
pathless objects use the same object identity and policy-local tables.  A file
descriptor carries a strong reference to that identity.  `SCM_RIGHTS`, Binder
FD transfer, pidfd operations, and io_uring never reinterpret a naked numeric
SID.

A transfer between sibling branches computes the common ancestor only to
select the policy paths that must authorize the transfer.  It does not
translate labels.  The receiver cannot use a transfer to bypass a policy
which constrained the sender or the object.

## Namespace selection

An active namespace FD identifies one state in the policy tree.  Selection for
future children follows PID-namespace semantics: the selecting task remains
in its current state and a subsequently created child receives the selected
state and a credential chain containing each ancestor.  Immediate self-join
remains a separate, single-threaded operation during compatibility migration.

The legacy 32-bit clone/setns namespace flag space has no free bit.  Therefore
the implementation must not silently reuse an existing clone flag.  The
stable namespace FD and an explicit selection operation are the authoritative
ABI unless a separately reviewed extension allocates a safe clone3/setns
encoding.

## Complexity

For ancestry depth `d`:

* local label lookup is expected O(1) per policy;
* complete authorization is Theta(d), because all policies must decide;
* creation and relabel are Theta(d);
* object storage is O(number of explicitly materialized policy/object pairs);
* missing entries require no allocation and resolve to local `unlabeled`.

An aggregate AVC cache may make a hot decision O(1) only when its key contains
the object identity, complete policy-chain identity, requested permissions,
classes, and every relevant policy sequence/chain epoch.

## Migration gates

1. The generic object-identity and policy-local table implementation passes
   lifetime, replacement, reload, quota, and concurrency tests.
2. Credential creation and namespace selection no longer require a label map.
3. Inode, superblock, mount, and file hooks use local labels and preserve
   revalidation of open files.
4. Every pathless and network object family uses the same identity model.
5. The map/view ABI and implementation have no callers and are removed.
6. The upstream SELinux behavior remains unchanged at depth zero.
7. KUnit, full build, QEMU systemd boot, OCI/Podman Android boot, and
   application-level SELinuxNS suites pass without an unexplained skip.

## Host-safety classification

The design preserves host monotonicity: every ancestor still authorizes every
operation, a child cannot write an ancestor table or policy, and resource use
is charged to the owning user namespace.  A normal post-specialize APK sees
the label and access results selected by the Android policy, matching physical
Android semantics; it gains no interface to observe or modify host-local
labels.  Privileged Android diagnostics may observe that label storage is
implemented by a kernel side table, but that implementation detail does not
grant host authority.
