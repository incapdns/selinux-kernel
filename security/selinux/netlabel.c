// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SELinux NetLabel Support
 *
 * This file provides the necessary glue to tie NetLabel into the SELinux
 * subsystem.
 *
 * Author: Paul Moore <paul@paul-moore.com>
 */

/*
 * (c) Copyright Hewlett-Packard Development Company, L.P., 2007, 2008
 */

#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/lsm_hooks.h>
#include <net/sock.h>
#include <net/netlabel.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "objsec.h"
#include "chain.h"
#include "namespace.h"
#include "object_label.h"
#include "security.h"
#include "netlabel.h"

/**
 * selinux_netlbl_sidlookup_cached - Cache a SID lookup
 * @skb: the packet
 * @family: the packet's address family
 * @secattr: the NetLabel security attributes
 * @sid: the SID
 *
 * Description:
 * Query the SELinux security server to lookup the correct SID for the given
 * security attributes.  If the query is successful, cache the result to speed
 * up future lookups.  Returns zero on success, negative values on failure.
 *
 */
static int selinux_netlbl_sidlookup_cached(
	struct selinux_state *state,
	struct sk_buff *skb,
	u16 family,
	struct netlbl_lsm_secattr *secattr,
	u32 *sid)
{
	char *context = NULL;
	u32 context_len;
	u32 origin_sid;
	int rc;

	if (state != init_selinux_state &&
	    (secattr->flags & (NETLBL_SECATTR_CACHE | NETLBL_SECATTR_SECID))) {
		origin_sid = secattr->flags & NETLBL_SECATTR_CACHE ?
			*(u32 *)secattr->cache->data : secattr->attr.secid;
		rc = security_sid_to_context(
			init_selinux_state,
			origin_sid,
			&context,
			&context_len);
		if (rc)
			return rc;
		rc = security_context_to_sid(
			state,
			context,
			context_len,
			sid,
			GFP_ATOMIC);
		kfree(context);
		return rc;
	}

	rc = security_netlbl_secattr_to_sid(state, secattr, sid);
	if (rc == 0 &&
	    state == init_selinux_state &&
	    (secattr->flags & NETLBL_SECATTR_CACHEABLE) &&
	    (secattr->flags & NETLBL_SECATTR_CACHE))
		netlbl_cache_add(skb, family, secattr);

	return rc;
}

/**
 * selinux_netlbl_sock_genattr - Generate the NetLabel socket secattr
 * @sk: the socket
 *
 * Description:
 * Generate the NetLabel security attributes for a socket, making full use of
 * the socket's attribute cache.  Returns a pointer to the security attributes
 * on success, or an ERR_PTR on failure.
 *
 */
static struct netlbl_lsm_secattr *selinux_netlbl_sock_genattr(struct sock *sk)
{
	int rc;
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_object_label_value label;
	struct netlbl_lsm_secattr *secattr;

	if (sksec->nlbl_secattr != NULL)
		return sksec->nlbl_secattr;

	secattr = netlbl_secattr_alloc(GFP_ATOMIC);
	if (secattr == NULL)
		return ERR_PTR(-ENOMEM);

	selinux_object_label_get_or_unlabeled(
		init_selinux_state,
		sksec->object,
		SECCLASS_SOCKET,
		&label);
	rc = security_netlbl_sid_to_secattr(
		init_selinux_state, label.sid, secattr);
	if (rc != 0) {
		netlbl_secattr_free(secattr);
		return ERR_PTR(rc);
	}
	sksec->nlbl_secattr = secattr;

	return secattr;
}

/**
 * selinux_netlbl_sock_getattr - Get the cached NetLabel secattr
 * @sk: the socket
 * @sid: the SID
 *
 * Query the socket's cached secattr and if the SID matches the cached value
 * return the cache, otherwise return NULL.
 *
 */
static struct netlbl_lsm_secattr *selinux_netlbl_sock_getattr(
							const struct sock *sk,
							u32 sid)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct netlbl_lsm_secattr *secattr = sksec->nlbl_secattr;

	if (secattr == NULL)
		return NULL;

	if ((secattr->flags & NETLBL_SECATTR_SECID) &&
	    (secattr->attr.secid == sid))
		return secattr;

	return NULL;
}

/**
 * selinux_netlbl_cache_invalidate - Invalidate the NetLabel cache
 *
 * Description:
 * Invalidate the NetLabel security attribute mapping cache.
 *
 */
void selinux_netlbl_cache_invalidate(void)
{
	netlbl_cache_invalidate();
}

/**
 * selinux_netlbl_err - Handle a NetLabel packet error
 * @skb: the packet
 * @family: the packet's address family
 * @error: the error code
 * @gateway: true if host is acting as a gateway, false otherwise
 *
 * Description:
 * When a packet is dropped due to a call to avc_has_perm() pass the error
 * code to the NetLabel subsystem so any protocol specific processing can be
 * done.  This is safe to call even if you are unsure if NetLabel labeling is
 * present on the packet, NetLabel is smart enough to only act when it should.
 *
 */
void selinux_netlbl_err(struct sk_buff *skb, u16 family, int error, int gateway)
{
	netlbl_skbuff_err(skb, family, error, gateway);
}

/**
 * selinux_netlbl_sk_security_free - Free the NetLabel fields
 * @sksec: the sk_security_struct
 *
 * Description:
 * Free all of the memory in the NetLabel fields of a sk_security_struct.
 *
 */
void selinux_netlbl_sk_security_free(struct sk_security_struct *sksec)
{
	if (!sksec->nlbl_secattr)
		return;

	netlbl_secattr_free(sksec->nlbl_secattr);
	sksec->nlbl_secattr = NULL;
	sksec->nlbl_state = NLBL_UNSET;
}

/**
 * selinux_netlbl_sk_security_reset - Reset the NetLabel fields
 * @sksec: the sk_security_struct
 *
 * Description:
 * Called when the NetLabel state of a sk_security_struct needs to be reset.
 * The caller is responsible for all the NetLabel sk_security_struct locking.
 *
 */
void selinux_netlbl_sk_security_reset(struct sk_security_struct *sksec)
{
	sksec->nlbl_state = NLBL_UNSET;
}

/**
 * selinux_netlbl_skbuff_getsid - Get the sid of a packet using NetLabel
 * @skb: the packet
 * @family: protocol family
 * @type: NetLabel labeling protocol type
 * @sid: the SID
 *
 * Description:
 * Call the NetLabel mechanism to get the security attributes of the given
 * packet and use those attributes to determine the correct context/SID to
 * assign to the packet.  Returns zero on success, negative values on failure.
 *
 */
int selinux_netlbl_skbuff_getsid(struct selinux_state *state,
				 struct sk_buff *skb,
				 u16 family,
				 u32 *type,
				 u32 *sid)
{
	int rc;
	struct netlbl_lsm_secattr secattr;

	if (!netlbl_enabled()) {
		*type = NETLBL_NLTYPE_NONE;
		*sid = SECSID_NULL;
		return 0;
	}

	netlbl_secattr_init(&secattr);
	rc = netlbl_skbuff_getattr(skb, family, &secattr);
	if (rc == 0 && secattr.flags != NETLBL_SECATTR_NONE)
		rc = selinux_netlbl_sidlookup_cached(
			state, skb, family, &secattr, sid);
	else
		*sid = SECSID_NULL;
	*type = secattr.type;
	netlbl_secattr_destroy(&secattr);

	return rc;
}

/**
 * selinux_netlbl_skbuff_setsid - Set the NetLabel on a packet given a sid
 * @skb: the packet
 * @family: protocol family
 * @sid: the SID
 *
 * Description
 * Call the NetLabel mechanism to set the label of a packet using @sid.
 * Returns zero on success, negative values on failure.
 *
 */
int selinux_netlbl_skbuff_setsid(struct selinux_state *state,
				 struct sk_buff *skb,
				 u16 family,
				 u32 sid)
{
	int rc;
	struct netlbl_lsm_secattr secattr_storage;
	struct netlbl_lsm_secattr *secattr = NULL;
	struct sock *sk;

	/* if this is a locally generated packet check to see if it is already
	 * being labeled by it's parent socket, if it is just exit */
	sk = skb_to_full_sk(skb);
	if (sk != NULL) {
		struct sk_security_struct *sksec = selinux_sock(sk);

		if (sksec->nlbl_state != NLBL_REQSKB)
			return 0;
		secattr = selinux_netlbl_sock_getattr(sk, sid);
	}
	if (secattr == NULL) {
		secattr = &secattr_storage;
		netlbl_secattr_init(secattr);
		rc = security_netlbl_sid_to_secattr(state, sid, secattr);
		if (rc != 0)
			goto skbuff_setsid_return;
	}

	rc = netlbl_skbuff_setattr(skb, family, secattr);

skbuff_setsid_return:
	if (secattr == &secattr_storage)
		netlbl_secattr_destroy(secattr);
	return rc;
}

/**
 * selinux_netlbl_sctp_assoc_request - Label an incoming sctp association.
 * @asoc: incoming association.
 * @skb: the packet.
 *
 * Description:
 * A new incoming connection is represented by @asoc, ......
 * Returns zero on success, negative values on failure.
 *
 */
int selinux_netlbl_sctp_assoc_request(struct sctp_association *asoc,
				     struct sk_buff *skb)
{
	int rc;
	struct netlbl_lsm_secattr secattr;
	struct sk_security_struct *sksec = selinux_sock(asoc->base.sk);
	struct sctp_security_struct *asocsec = selinux_sctp(asoc);
	struct selinux_object_label_value root_label;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;

	if (asoc->base.sk->sk_family != PF_INET &&
	    asoc->base.sk->sk_family != PF_INET6)
		return 0;

	netlbl_secattr_init(&secattr);
	selinux_object_label_get_or_unlabeled(
		init_selinux_state,
		asocsec->object,
		SECCLASS_SCTP_SOCKET,
		&root_label);
	rc = security_netlbl_sid_to_secattr(
		init_selinux_state, root_label.sid, &secattr);
	if (rc != 0)
		goto assoc_request_return;

	/* Move skb hdr address info to a struct sockaddr and then call
	 * netlbl_conn_setattr().
	 */
	if (ip_hdr(skb)->version == 4) {
		addr4.sin_family = AF_INET;
		addr4.sin_addr.s_addr = ip_hdr(skb)->saddr;
		rc = netlbl_conn_setattr(asoc->base.sk, (void *)&addr4, &secattr);
	} else if (IS_ENABLED(CONFIG_IPV6) && ip_hdr(skb)->version == 6) {
		addr6.sin6_family = AF_INET6;
		addr6.sin6_addr = ipv6_hdr(skb)->saddr;
		rc = netlbl_conn_setattr(asoc->base.sk, (void *)&addr6, &secattr);
	} else {
		rc = -EAFNOSUPPORT;
	}

	if (rc == 0)
		sksec->nlbl_state = NLBL_LABELED;

assoc_request_return:
	netlbl_secattr_destroy(&secattr);
	return rc;
}

/**
 * selinux_netlbl_inet_conn_request - Label an incoming stream connection
 * @req: incoming connection request socket
 * @family: the request socket's address family
 *
 * Description:
 * A new incoming connection request is represented by @req, we need to label
 * the new request_sock here and the stack will ensure the on-the-wire label
 * will get preserved when a full sock is created once the connection handshake
 * is complete.  Returns zero on success, negative values on failure.
 *
 */
int selinux_netlbl_inet_conn_request(struct request_sock *req, u16 family)
{
	int rc;
	struct netlbl_lsm_secattr secattr;
	struct request_sock_security_struct *reqsec =
		selinux_request_sock(req);
	struct selinux_object_label_value root_label;

	if (family != PF_INET && family != PF_INET6)
		return 0;

	netlbl_secattr_init(&secattr);
	selinux_object_label_get_or_unlabeled(
		init_selinux_state,
		reqsec->object,
		SECCLASS_TCP_SOCKET,
		&root_label);
	rc = security_netlbl_sid_to_secattr(
		init_selinux_state, root_label.sid, &secattr);
	if (rc != 0)
		goto inet_conn_request_return;
	rc = netlbl_req_setattr(req, &secattr);
inet_conn_request_return:
	netlbl_secattr_destroy(&secattr);
	return rc;
}

/**
 * selinux_netlbl_inet_csk_clone - Initialize the newly created sock
 * @sk: the new sock
 * @family: the sock's address family
 *
 * Description:
 * A new connection has been established using @sk, we've already labeled the
 * socket via the request_sock struct in selinux_netlbl_inet_conn_request() but
 * we need to set the NetLabel state here since we now have a sock structure.
 *
 */
void selinux_netlbl_inet_csk_clone(struct sock *sk, u16 family)
{
	struct sk_security_struct *sksec = selinux_sock(sk);

	if (family == PF_INET || family == PF_INET6)
		sksec->nlbl_state = NLBL_LABELED;
	else
		sksec->nlbl_state = NLBL_UNSET;
}

/**
 * selinux_netlbl_sctp_sk_clone - Copy state to the newly created sock
 * @sk: current sock
 * @newsk: the new sock
 *
 * Description:
 * Called whenever a new socket is created by accept(2) or sctp_peeloff(3).
 */
void selinux_netlbl_sctp_sk_clone(struct sock *sk, struct sock *newsk)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct sk_security_struct *newsksec = selinux_sock(newsk);

	newsksec->nlbl_state = sksec->nlbl_state;
}

/**
 * selinux_netlbl_socket_post_create - Label a socket using NetLabel
 * @sk: the sock to label
 * @family: protocol family
 *
 * Description:
 * Attempt to label a socket using the NetLabel mechanism using the given
 * SID.  Returns zero values on success, negative values on failure.
 *
 */
int selinux_netlbl_socket_post_create(struct sock *sk, u16 family)
{
	int rc;
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct netlbl_lsm_secattr *secattr;

	if (family != PF_INET && family != PF_INET6)
		return 0;

	secattr = selinux_netlbl_sock_genattr(sk);
	if (IS_ERR(secattr))
		return PTR_ERR(secattr);
	/* On socket creation, replacement of IP options is safe even if
	 * the caller does not hold the socket lock.
	 */
	rc = netlbl_sock_setattr(sk, family, secattr, true);
	switch (rc) {
	case 0:
		sksec->nlbl_state = NLBL_LABELED;
		break;
	case -EDESTADDRREQ:
		sksec->nlbl_state = NLBL_REQSKB;
		rc = 0;
		break;
	}

	return rc;
}

/**
 * selinux_netlbl_sock_rcv_skb - Do an inbound access check using NetLabel
 * @sksec: the sock's sk_security_struct
 * @skb: the packet
 * @family: protocol family
 * @ad: the audit data
 *
 * Description:
 * Fetch the NetLabel security attributes from @skb and perform an access check
 * against the receiving socket.  Returns zero on success, negative values on
 * error.
 *
 */
struct selinux_netlbl_receive_request {
	struct sk_security_struct *security;
	struct netlbl_lsm_secattr *secattr;
	struct sk_buff *skb;
	u16 family;
};

static int selinux_resolve_netlbl_receive(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	const struct selinux_netlbl_receive_request *request = data;
	struct selinux_object_label_value socket_label;
	u32 nlbl_sid;
	int rc;

	selinux_object_label_get_or_unlabeled(
		state,
		request->security->object,
		SECCLASS_SOCKET,
		&socket_label);
	rc = selinux_netlbl_sidlookup_cached(
		state,
		request->skb,
		request->family,
		request->secattr,
		&nlbl_sid);
	if (rc)
		return rc;

	permission->ssid = socket_label.sid;
	permission->tsid = nlbl_sid ? nlbl_sid : SECINITSID_UNLABELED;
	permission->tclass = socket_label.sclass ?
		socket_label.sclass : SECCLASS_SOCKET;
	permission->decided =
		!selinux_policycap_netpeer(state) &&
		socket_label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS;
	switch (permission->tclass) {
	case SECCLASS_UDP_SOCKET:
		permission->requested = UDP_SOCKET__RECVFROM;
		break;
	case SECCLASS_TCP_SOCKET:
		permission->requested = TCP_SOCKET__RECVFROM;
		break;
	default:
		permission->requested = RAWIP_SOCKET__RECVFROM;
		break;
	}
	return 0;
}

int selinux_netlbl_sock_rcv_skb(struct sk_security_struct *sksec,
				struct sk_buff *skb,
				u16 family,
				struct common_audit_data *ad)
{
	struct netlbl_lsm_secattr secattr;
	struct selinux_netlbl_receive_request request = {
		.security = sksec,
		.secattr = &secattr,
		.skb = skb,
		.family = family,
	};
	const struct cred *creator = sksec->creator_cred;
	int rc;

	if (!netlbl_enabled())
		return 0;
	if (!creator)
		return -ESTALE;

	netlbl_secattr_init(&secattr);
	rc = netlbl_skbuff_getattr(skb, family, &secattr);
	if (rc)
		goto out;
	if (secattr.flags == NETLBL_SECATTR_NONE) {
		secattr.flags = NETLBL_SECATTR_SECID;
		secattr.attr.secid = SECINITSID_UNLABELED;
	}
	rc = selinux_chain_has_custom_perm(
		creator,
		sksec->object,
		NULL,
		selinux_resolve_netlbl_receive,
		&request,
		ad);
	if (rc && secattr.attr.secid != SECINITSID_UNLABELED)
		netlbl_skbuff_err(skb, family, rc, 0);
out:
	netlbl_secattr_destroy(&secattr);
	return rc;
}

/**
 * selinux_netlbl_option - Is this a NetLabel option
 * @level: the socket level or protocol
 * @optname: the socket option name
 *
 * Description:
 * Returns true if @level and @optname refer to a NetLabel option.
 * Helper for selinux_netlbl_socket_setsockopt().
 */
static inline int selinux_netlbl_option(int level, int optname)
{
	return (level == IPPROTO_IP && optname == IP_OPTIONS) ||
		(level == IPPROTO_IPV6 && optname == IPV6_HOPOPTS);
}

/**
 * selinux_netlbl_socket_setsockopt - Do not allow users to remove a NetLabel
 * @sock: the socket
 * @level: the socket level or protocol
 * @optname: the socket option name
 *
 * Description:
 * Check the setsockopt() call and if the user is trying to replace the IP
 * options on a socket and a NetLabel is in place for the socket deny the
 * access; otherwise allow the access.  Returns zero when the access is
 * allowed, -EACCES when denied, and other negative values on error.
 *
 */
int selinux_netlbl_socket_setsockopt(struct socket *sock,
				     int level,
				     int optname)
{
	int rc = 0;
	struct sock *sk = sock->sk;
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct netlbl_lsm_secattr secattr;

	if (selinux_netlbl_option(level, optname) &&
	    (sksec->nlbl_state == NLBL_LABELED ||
	     sksec->nlbl_state == NLBL_CONNLABELED)) {
		netlbl_secattr_init(&secattr);
		lock_sock(sk);
		/* call the netlabel function directly as we want to see the
		 * on-the-wire label that is assigned via the socket's options
		 * and not the cached netlabel/lsm attributes */
		rc = netlbl_sock_getattr(sk, &secattr);
		release_sock(sk);
		if (rc == 0)
			rc = -EACCES;
		else if (rc == -ENOMSG)
			rc = 0;
		netlbl_secattr_destroy(&secattr);
	}

	return rc;
}

/**
 * selinux_netlbl_socket_connect_helper - Help label a client-side socket on
 * connect
 * @sk: the socket to label
 * @addr: the destination address
 *
 * Description:
 * Attempt to label a connected socket with NetLabel using the given address.
 * Returns zero values on success, negative values on failure.
 *
 */
static int selinux_netlbl_socket_connect_helper(struct sock *sk,
						struct sockaddr *addr)
{
	int rc;
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct netlbl_lsm_secattr *secattr;

	/* connected sockets are allowed to disconnect when the address family
	 * is set to AF_UNSPEC, if that is what is happening we want to reset
	 * the socket */
	if (addr->sa_family == AF_UNSPEC) {
		netlbl_sock_delattr(sk);
		sksec->nlbl_state = NLBL_REQSKB;
		rc = 0;
		return rc;
	}
	secattr = selinux_netlbl_sock_genattr(sk);
	if (IS_ERR(secattr))
		return PTR_ERR(secattr);

	rc = netlbl_conn_setattr(sk, addr, secattr);
	if (rc == 0)
		sksec->nlbl_state = NLBL_CONNLABELED;

	return rc;
}

/**
 * selinux_netlbl_socket_connect_locked - Label a client-side socket on
 * connect
 * @sk: the socket to label
 * @addr: the destination address
 *
 * Description:
 * Attempt to label a connected socket that already has the socket locked
 * with NetLabel using the given address.
 * Returns zero values on success, negative values on failure.
 *
 */
int selinux_netlbl_socket_connect_locked(struct sock *sk,
					 struct sockaddr *addr)
{
	struct sk_security_struct *sksec = selinux_sock(sk);

	if (sksec->nlbl_state != NLBL_REQSKB &&
	    sksec->nlbl_state != NLBL_CONNLABELED)
		return 0;

	return selinux_netlbl_socket_connect_helper(sk, addr);
}

/**
 * selinux_netlbl_socket_connect - Label a client-side socket on connect
 * @sk: the socket to label
 * @addr: the destination address
 *
 * Description:
 * Attempt to label a connected socket with NetLabel using the given address.
 * Returns zero values on success, negative values on failure.
 *
 */
int selinux_netlbl_socket_connect(struct sock *sk, struct sockaddr *addr)
{
	int rc;

	lock_sock(sk);
	rc = selinux_netlbl_socket_connect_locked(sk, addr);
	release_sock(sk);

	return rc;
}
