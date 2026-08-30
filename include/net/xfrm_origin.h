/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XFRM_ORIGIN_H
#define _NET_XFRM_ORIGIN_H

struct request_sock;
struct sk_buff;
struct sock;

/*
 * Object which supplied flowi_secid.  This is a typed borrowed reference: the
 * caller keeps the selected object alive for the complete synchronous XFRM
 * lookup, and each LSM takes its own durable reference before publication.
 * The scalar flowi_secid remains only a compatibility mirror.
 */
enum xfrm_flow_origin_kind {
	XFRM_FLOW_ORIGIN_NONE,
	XFRM_FLOW_ORIGIN_SOCK,
	XFRM_FLOW_ORIGIN_REQUEST,
	XFRM_FLOW_ORIGIN_SKB,
};

struct xfrm_flow_origin {
	enum xfrm_flow_origin_kind kind;
	union {
		const struct sock *sk;
		const struct request_sock *req;
		const struct sk_buff *skb;
	};
};

static inline struct xfrm_flow_origin xfrm_flow_origin_none(void)
{
	return (struct xfrm_flow_origin) { .kind = XFRM_FLOW_ORIGIN_NONE };
}

static inline struct xfrm_flow_origin
xfrm_flow_origin_sock(const struct sock *sk)
{
	return (struct xfrm_flow_origin) {
		.kind = sk ? XFRM_FLOW_ORIGIN_SOCK : XFRM_FLOW_ORIGIN_NONE,
		.sk = sk,
	};
}

static inline struct xfrm_flow_origin
xfrm_flow_origin_request(const struct request_sock *req)
{
	return (struct xfrm_flow_origin) {
		.kind = req ? XFRM_FLOW_ORIGIN_REQUEST : XFRM_FLOW_ORIGIN_NONE,
		.req = req,
	};
}

static inline struct xfrm_flow_origin
xfrm_flow_origin_skb(const struct sk_buff *skb)
{
	return (struct xfrm_flow_origin) {
		.kind = skb ? XFRM_FLOW_ORIGIN_SKB : XFRM_FLOW_ORIGIN_NONE,
		.skb = skb,
	};
}

#endif /* _NET_XFRM_ORIGIN_H */
