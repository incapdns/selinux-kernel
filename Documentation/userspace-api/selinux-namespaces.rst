.. SPDX-License-Identifier: GPL-2.0

===============================
SELinux namespace control file
===============================

When ``CONFIG_SECURITY_SELINUX_NS`` is enabled, selinuxfs exposes
``ns_create``.  ``SELINUX_NS_IOC_CREATE`` on that file returns a close-on-exec
namespace-control file descriptor.  The descriptor represents one dormant
direct child of the caller's current SELinux namespace and is a real ``nsfs``
file with a unique inode and non-reused ``NS_GET_ID`` identity.  A dormant
namespace is addressable only through its FD; activation publishes it in the
namespace tree.

The ABI declarations are in ``<linux/selinux_ns.h>``.  A normal sequence is::

    control = open("/sys/fs/selinux/ns_create", O_RDONLY | O_CLOEXEC);
    nsfd = ioctl(control, SELINUX_NS_IOC_CREATE);
    ioctl(nsfd, SELINUX_NS_IOC_LOAD_POLICY, &policy);
    ioctl(nsfd, SELINUX_NS_IOC_ADD_MAP, &parent_to_child);
    ioctl(nsfd, SELINUX_NS_IOC_ADD_MAP, &child_to_parent);
    ioctl(nsfd, SELINUX_NS_IOC_ACTIVATE);
    setns(nsfd, 0);

The dedicated ``SELINUX_NS_IOC_JOIN`` remains equivalent for callers that do
not need the generic namespace syscall.  The namespace type is zero because
the 32-bit clone/setns flag space has no unused namespace bit; consequently
``setns`` must be called with a zero ``nstype``.  SELinux namespaces cannot be
selected as one component of a pidfd multi-namespace set.

Policy and maps can be configured only while the namespace is dormant and only
by a task whose current SELinux namespace is its direct parent.  The caller
also needs ``CAP_SYS_ADMIN`` in the owning user namespace and the existing
SELinux namespace-unshare permission in its complete credential chain.

``SELINUX_NS_IOC_LOAD_POLICY`` accepts exactly one initial binary policy.  Its
``flags`` field must be zero.  Policy replacement through the control FD is
deliberately rejected because replacing a policy after map construction would
invalidate the contexts used to build those maps.

``SELINUX_NS_IOC_ADD_MAP`` adds one directional mapping.  Context lengths do
not include a trailing NUL, embedded NUL bytes are rejected, and ``direction``
is either ``SELINUX_NS_MAP_PARENT_TO_CHILD`` (zero) or
``SELINUX_NS_MAP_CHILD_TO_PARENT`` (one).  ``flags`` must be zero.  Both
contexts are resolved by the kernel in their explicitly selected policies;
userspace never supplies numeric SIDs.

``SELINUX_NS_IOC_ACTIVATE`` seals and publishes the parent's immutable map and
then makes the target joinable.  At least one entry in each direction is
required.  Any error leaves it unjoinable.  Mapping changes after activation
fail closed.

``SELINUX_NS_IOC_JOIN`` is allowed only from the direct parent.  The calling
task must be single-threaded and must not retain a selinuxfs policy/status VMA.
Its parent SID is resolved through the sealed parent-to-child map; absence of a
mapping fails the join.  All checks and allocations precede ``commit_creds()``,
so failure cannot install a partial chain.
Policy reloads do not permanently stale an active control FD: the immutable
canonical target context is rebound to the current target policy while both
policy mutexes are held, and a context removed by reload fails closed.
The policy digest is part of the same immutable RCU-published policy object as
the sequence number.  It hashes the accepted binary policy plus the ordered
effective boolean values.  Traditional selinuxfs reload and boolean updates
therefore publish a new sequence and effective digest atomically.

``SELINUX_NS_IOC_GET_INFO`` reports the stable namespace ID, parent ID, depth,
and initialized/sealed/active flags.  ``GET_METADATA`` additionally
reports namespace and provenance-domain IDs, policy sequence, immutable map
identity/generation, directional entry counts, and SHA-256 digests of the
accepted binary policy and ordered map transcript.  Closing the last FD
destroys an unjoined namespace.  After a successful join, credentials retain
the state; the ordinary refcount/RCU teardown runs only after the last
credential and FD reference is gone.  Active tasks expose
``/proc/PID/ns/selinux``.

The older ``LSM_ATTR_UNSHARE`` operation remains available.  It creates an
immediately active but initially unmapped child and is consequently an
isolation-oriented, fail-closed interface rather than the two-phase mapped
runtime interface.

``ACTIVATE_RESTORE`` compares the expected namespace/parent identity, first
policy sequence, map generation, policy digest, and ordered-map digest before
publishing anything.  A mismatch returns ``ESTALE``.  The transcript hashes a
versioned domain separator followed by each successfully inserted mapping in
insertion order, encoded as little-endian direction/source-length/target-length
and the two context byte strings.

``CREATE_RESTORE`` is issued on ``ns_create`` and is restricted to a caller
with ``CAP_SYS_ADMIN`` in the initial user namespace plus the SELinux namespace
creation permission.  It accepts ``size``, zero ``flags``, ``expected_id`` and
``expected_parent_id``.  The parent must be the caller's current SELinux
namespace.  Global namespace IDs are monotonic and never reused.  Restore
atomically advances the global high-water mark to ``expected_id``, which must
be larger than the current mark and no larger than ``S64_MAX``.  Gaps are
permanently consumed, so SELinux namespace restore must replay requested IDs in
increasing order, but need not recreate intervening namespaces of other types.
A stale or out-of-order request returns ``ESTALE`` without consuming an ID.
Because a successful request can consume a large gap, this operation is
intentionally restricted to host-init authority.

This is sufficient for deterministic validation and same-kernel restoration
when the original namespace FD survives, or when namespace-ID allocation is
replayed exactly.  It is not a complete cross-boot CRIU facility: there is no
support for restoring IDs out of increasing order, no pidfd setns bit for
SELinux, and CRIU userspace does not yet serialize this metadata.  Restore must
fail rather than substitute a new identity.  Those external ABI/tooling gaps
remain open.
