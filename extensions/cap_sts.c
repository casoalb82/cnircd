/*
 * chatnet/cap_sts.c -- IRCv3 "sts" (Strict Transport Security) client
 * capability, for the K9/Atheme migration project's public leaf.
 *
 * Not a stock solanum module -- solanum has no built-in STS support at
 * all (confirmed by grepping the upstream source for "sts"/CAP_STS/
 * draft/sts, nothing), so this is a new module, modeled directly on
 * modules/cap_server_time.c and modules/m_sasl.c's own capdata_sasl
 * pattern (struct ClientCapability's .data callback is exactly how SASL
 * advertises its mechanism list as a CAP value -- same mechanism reused
 * here for the sts=... policy string).
 *
 * Policy: plaintext connections get "sts=port=6697,duration=N" (the real
 * TLS port + how long to remember the upgrade); TLS connections get
 * "sts=duration=N" (no port -- they're already secure, this just renews
 * the policy so it doesn't expire on a client that keeps reconnecting
 * over TLS). IsSecure() is the same macro extensions/m_webirc.c already
 * uses to check a client's actual connection security.
 *
 * Duration deliberately starts short (1 day, not the commonly-cited
 * 30-day value) -- this is the IRCv3 STS spec's own recommended rollout
 * practice: a wrong/broken policy at a long duration locks clients out
 * of the plaintext port they'd need to fall back to. Safe to raise once
 * this has run a few days without incident.
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "s_serv.h"

static uint64_t CLICAP_STS = 0;

#define STS_PORT "6697"
#define STS_DURATION "86400"

static char sts_policy_plain[BUFSIZE];
static char sts_policy_secure[BUFSIZE];

static const char cap_sts_desc[] =
	"Provides the STS (Strict Transport Security) client capability";

static const char *
sts_data(struct Client *client_p)
{
	return IsSecure(client_p) ? sts_policy_secure : sts_policy_plain;
}

static struct ClientCapability capdata_sts = {
	.data = sts_data,
};

mapi_cap_list_av2 sts_cap_list[] = {
	{ MAPI_CAP_CLIENT, "sts", &capdata_sts, &CLICAP_STS },
	{ 0, NULL, NULL, NULL },
};

static int
sts_modinit(void)
{
	snprintf(sts_policy_plain, sizeof sts_policy_plain,
	         "port=%s,duration=%s", STS_PORT, STS_DURATION);
	snprintf(sts_policy_secure, sizeof sts_policy_secure,
	         "duration=%s", STS_DURATION);
	return 0;
}

DECLARE_MODULE_AV2(cap_sts, sts_modinit, NULL, NULL, NULL, NULL, sts_cap_list, NULL, cap_sts_desc);
