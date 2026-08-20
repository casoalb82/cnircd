/*
 * Solanum: a slightly advanced ircd
 * cn_ip_cloak.c: ChatNet-branded IP cloaking for anonymous users
 *
 * Fork of extensions/ip_cloaking_4.0.c (originally by nenolod, FNV
 * variant by Elizabeth, 2008), modified 2026-08-12 for ChatNet to
 * prepend a "CN-" brand prefix to the cloaked host/IP, so anonymous
 * users get a recognisable ChatNet cloak instead of a bare mangled
 * hostname. Cloaking algorithm itself (which octets/labels stay real
 * vs get FNV-scrambled) is completely unchanged from upstream -- only
 * the final output gets a "CN-" prefix tacked on.
 *
 * Deliberately per-user unique (derived from the real host/IP), not a
 * single shared mask for every anonymous connection -- a single shared
 * mask would mean one kline/gline hits every anonymous user on the
 * network at once. Registered+identified NickServ accounts still get
 * their own "user/<account>" cloak instead of this one, unconditionally
 * overwritten by nickserv/vhost.c's vhost_on_identify() on IDENTIFY/SASL
 * -- see custom-modules/nickserv/ns_defaultcloak.c on the atheme side.
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"

#define CN_CLOAK_PREFIX "CN-"

static const char cn_ip_cloak_desc[] =
	"ChatNet-branded IP cloaking module that uses user mode +x";

static int
_modinit(void)
{
	/* add the usermode to the available slot */
	user_modes['x'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	/* disable the umode and remove it from the available list */
	user_modes['x'] = 0;
	construct_umodebuf();
}

static void check_umode_change(void *data);
static void check_new_user(void *data);
mapi_hfn_list_av1 cn_ip_cloak_hfnlist[] = {
	{ "umode_changed", check_umode_change },
	{ "new_local_user", check_new_user },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(cn_ip_cloak, _modinit, _moddeinit, NULL, NULL,
			cn_ip_cloak_hfnlist, NULL, NULL, cn_ip_cloak_desc);

static void
distribute_hostchange(struct Client *client_p, char *newhost)
{
	if (newhost != client_p->orighost)
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
			newhost);
	else
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :hostname reset",
			newhost);

	sendto_server(NULL, NULL,
		CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);
	sendto_server(NULL, NULL,
		CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
		use_id(&me), use_id(client_p), newhost);

	change_nick_user_host(client_p, client_p->name, client_p->username, newhost, 0, "Changing host");

	if (newhost != client_p->orighost)
		SetDynSpoof(client_p);
	else
		ClearDynSpoof(client_p);
}

/* Same octet/label-selection logic as upstream ip_cloaking_4.0 --
 * builds the mangled form into a scratch buffer first, then prefixes
 * it with "CN-" into outbuf. */

static void
do_host_cloak_ip(const char *inbuf, char *outbuf)
{
	/* None of the characters in this table can be valid in an IP */
	char chartable[] = "ghijklmnopqrstuvwxyz";
	char scratch[HOSTLEN + 1];
	char *tptr;
	uint32_t accum = fnv_hash((const unsigned char*) inbuf, 32);
	int sepcount = 0;
	int totalcount = 0;
	int ipv6 = 0;

	rb_strlcpy(scratch, inbuf, sizeof scratch);

	if (strchr(scratch, ':'))
	{
		ipv6 = 1;

		/* Damn you IPv6...
		 * We count the number of colons so we can calculate how much
		 * of the host to cloak. This is because some hostmasks may not
		 * have as many octets as we'd like.
		 *
		 * We have to do this ahead of time because doing this during
		 * the actual cloaking would get ugly
		 */
		for (tptr = scratch; *tptr != '\0'; tptr++)
			if (*tptr == ':')
				totalcount++;
	}
	else if (!strchr(scratch, '.'))
	{
		rb_strlcpy(outbuf, inbuf, HOSTLEN + 1);
		return;
	}

	for (tptr = scratch; *tptr != '\0'; tptr++)
	{
		if (*tptr == ':' || *tptr == '.')
		{
			sepcount++;
			continue;
		}

		if (ipv6 && sepcount < totalcount / 2)
			continue;

		if (!ipv6 && sepcount < 2)
			continue;

		*tptr = chartable[(*tptr + accum) % 20];
		accum = (accum << 1) | (accum >> 31);
	}

	snprintf(outbuf, HOSTLEN + 1, CN_CLOAK_PREFIX "%s", scratch);
}

static void
do_host_cloak_host(const char *inbuf, char *outbuf)
{
	char b26_alphabet[] = "abcdefghijklmnopqrstuvwxyz";
	char scratch[HOSTLEN + 1];
	char *tptr;
	uint32_t accum = fnv_hash((const unsigned char*) inbuf, 32);

	rb_strlcpy(scratch, inbuf, sizeof scratch);

	/* pass 1: scramble first section of hostname using base26
	 * alphabet toasted against the FNV hash of the string.
	 *
	 * numbers are not changed at this time, only letters.
	 */
	for (tptr = scratch; *tptr != '\0'; tptr++)
	{
		if (*tptr == '.')
			break;

		if (isdigit((unsigned char)*tptr) || *tptr == '-')
			continue;

		*tptr = b26_alphabet[(*tptr + accum) % 26];

		/* Rotate one bit to avoid all digits being turned odd or even */
		accum = (accum << 1) | (accum >> 31);
	}

	/* pass 2: scramble each number in the address */
	for (tptr = scratch; *tptr != '\0'; tptr++)
	{
		if (isdigit((unsigned char)*tptr))
			*tptr = '0' + (*tptr + accum) % 10;

		accum = (accum << 1) | (accum >> 31);
	}

	snprintf(outbuf, HOSTLEN + 1, CN_CLOAK_PREFIX "%s", scratch);
}

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* didn't change +h umode, we don't need to do anything */
	if (!((data->oldumodes ^ source_p->umodes) & user_modes['x']))
		return;

	if (source_p->umodes & user_modes['x'])
	{
		if (IsIPSpoof(source_p) || source_p->localClient->mangledhost == NULL || (IsDynSpoof(source_p) && strcmp(source_p->host, source_p->localClient->mangledhost)))
		{
			source_p->umodes &= ~user_modes['x'];
			return;
		}
		if (strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->localClient->mangledhost);
		}
		else /* not really nice, but we need to send this numeric here */
			sendto_one_numeric(source_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
				source_p->host);
	}
	else if (!(source_p->umodes & user_modes['x']))
	{
		if (source_p->localClient->mangledhost != NULL &&
				!strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->orighost);
		}
	}
}

static void
check_new_user(void *vdata)
{
	struct Client *source_p = (void *)vdata;

	if (IsIPSpoof(source_p))
	{
		source_p->umodes &= ~user_modes['x'];
		return;
	}
	source_p->localClient->mangledhost = rb_malloc(HOSTLEN + 1);
	if (!irccmp(source_p->orighost, source_p->sockhost))
		do_host_cloak_ip(source_p->orighost, source_p->localClient->mangledhost);
	else
		do_host_cloak_host(source_p->orighost, source_p->localClient->mangledhost);
	if (IsDynSpoof(source_p))
		source_p->umodes &= ~user_modes['x'];
	if (source_p->umodes & user_modes['x'])
	{
		rb_strlcpy(source_p->host, source_p->localClient->mangledhost, sizeof(source_p->host));
		if (irccmp(source_p->host, source_p->orighost))
			SetDynSpoof(source_p);
	}
}
