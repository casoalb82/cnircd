# cnircd -- ChatNet's Solanum fork

This is [Solanum](https://github.com/solanum-ircd/solanum), forked at
commit `48db98ab2b4191ba75047a74c79a353e4f82bf5a`, with the patches
[ChatNet](https://chatnet.gg/) runs in production applied on top. If
you're linking a leaf into ChatNet, build this instead of vanilla
Solanum -- it saves you from re-discovering the same build/runtime
issues we already hit.

Get the leaf config template and your SID/link password from
[chatnet.gg/routing](https://chatnet.gg/routing.html) -- this repo is
just the ircd itself.

## Patches on top of upstream, in commit order

1. **Drop `arc4random_stir()` calls** -- glibc >= 2.36 dropped this
   legacy BSD reseed call; `librb`'s no-TLS PRNG backend still called
   it, which is an undefined-reference link failure on current
   distros (Debian bookworm and newer). Safe to drop: glibc's
   `arc4random()` already self-reseeds.
2. **`authd`: pin nameserver validation to `PF_INET`** -- upstream's
   `PF_UNSPEC` probe returns `EAFNOSUPPORT` in some container
   runtimes, which kills DNS resolution (and then the whole ircd, via
   a separate respawn-path bug) even though real nameservers are
   configured. ChatNet only uses IPv4 nameservers, so this sidesteps
   the unsupported probe rather than fixing it generally -- if you
   need real dual-stack nameserver validation, don't cherry-pick this
   one.
3. **Real build date** instead of the literal `__DATE__ at __TIME__`
   placeholder in `/VERSION` and the 003 numeric (upstream's meson
   build never ported the old autotools path's actual `date` call).
4. **Hide channel mode `+P` from `MODE` queries** -- ChatNet-specific.
   `+P` marks a channel as permanent (survives its last member
   parting) for services-side use; this keeps that mechanism intact
   but stops it from showing up in a regular `/mode #chan` unless the
   querying client holds the `auspex:cmodes` oper privilege. Skip or
   revert this one if your network doesn't want that behavior --
   grant `auspex:cmodes` to every oper privset to get full visibility
   back with zero source changes.

Each patch is its own commit with a full explanation in the commit
message -- `git log` for the details, this file is just the index.

## Building

Same as upstream Solanum -- see `INSTALL.md`. If you're containerizing
it, watch Docker's default `nofile` ulimit: it's often high enough
that Solanum's fd-indexed table sizing tries to allocate a huge amount
of memory and segfaults at startup. Cap it explicitly (ChatNet uses
`65536`).

## Staying in sync with upstream

This fork does not track upstream Solanum automatically. If you want
newer upstream fixes, rebase this branch's 4 commits onto whatever
upstream commit you want and re-verify each patch still applies
cleanly.
