# nu.harness (core)

Copy of the khėnsu agent harness for anyone working in **khensu-core** (Rust, UniFFI, MLS, Outfox).

Canonical skill: [`nu-harness`](https://github.com/elliott-wave-labs/khensu-specs/blob/main/.cursor/skills/nu-harness/SKILL.md) · live: [skills.agent](https://khensu.nu/skills-agent) · specs: [`nu.harness.md`](https://github.com/elliott-wave-labs/khensu-specs/blob/main/nu.harness.md)

Only **nu-harness** is published on the skills.agent site. Other skills stay private.

---

# nu.harness

Agent harness for khėnsu.ñü work across Cursor and other open agents. Skill: `nu-harness` (`~/.cursor/skills/nu-harness` and `.cursor/skills/nu-harness` in this repo).

## ALWAYS LIVE — product HTTPS

Product hosts share `moqom-products-*` on the sites HTTPS proxy. A **PROVISIONING** products cert (or any **NXDOMAIN / wrong-A** cert left on the proxy) makes every product host present the wrong certificate (`CN=elliottwave.dev`). Browsers then block CSS/JS and the site looks like unstyled HTML. **Treat that as a full outage.**

### Rules

1. Before adding any host to shared `product_hosts`, `dig +short HOST A` must return `34.107.228.246` (not NXDOMAIN). `dig +short HOST AAAA` must be empty (or also that IP).
2. New subdomains use `own_certificate = true` so they cannot recreate the shared pack.
3. Never leave an apply that replaced `moqom-products-*` until `managed.status` is `ACTIVE` and `openssl s_client -servername bi.khensu.nu` is not `elliottwave.dev`.
4. **NXDOMAIN / wrong-A certs never stay on the https proxy.** Remove them immediately. That is what breaks SNI for bi/waves (seen with dead API hosts).
5. **own_certificate bootstrap (Google requirement):** a Google-managed cert becomes `ACTIVE` only after it is **attached** to the target HTTPS proxy **and** DNS A → `34.107.228.246`. Waiting for ACTIVE *before* attach is a deadlock (`FAILED_NOT_VISIBLE` forever). Procedure:
   1. `dig` / `host` preflight (rule 1) — abort if wrong.
   2. Create the own cert; attach it to `moqom-sites` **with all existing ACTIVE certs kept**.
   3. Stay on the apply: poll until own cert `ACTIVE`, and every 30s confirm `bi.khensu.nu` still `CN=bi.khensu.nu` + HTTP 200. If bi breaks, detach the new certs immediately.
   4. Only then call the host shipped.
6. **Done means matching CN.** Apex (`https://khensu.nu/avatars`) is not product-host HTTPS. Do not mark `avatars.khensu.nu` / `indra.og.khensu.nu` done until:
   ```bash
   echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null \
     | openssl x509 -noout -subject   # must contain HOST, not elliottwave.dev
   curl -sI --max-time 10 https://HOST/ | head -1   # HTTP/2 200
   ```
7. Multi-label hosts (`indra.og.khensu.nu`) are **not** covered by `*.khensu.nu`. Add an explicit A (Hover + Cloud DNS zone `khensu-nu`).

SLA page: [https://khensu.nu/sla](https://khensu.nu/sla) (`sla.khensu.nu` only after DNS + own cert ACTIVE). Full public notice: [`PUBLIC.md`](PUBLIC.md).

## When to use

khensu.nu sites, product hosts, GitHub repos under elliott-wave-labs, App Store / sideload install, dead-man's switch, SLA, SSL/terraform for sites.

## Fixed rules

1. **Publish sites immediately.** Never hold for a patent filing.
2. **Keep code public.** First-party `khensu-*` repos stay public.
3. **Install without stores.** Safari PWA, GitHub IPA sideload, `xcodegen` / Xcode. Team ID `LHS49D8RYY`.
4. **Desktop vs mobile.** Desktop perfect → only `@media` mobile rules.
5. **Display names.** People see khėnsu.ñü, ñü.ŵævẽš, …; code/URLs stay ASCII.
6. **Commands** start with `~`, never `/`.
7. **Wording.** Gift of freedom, privacy, basic income — never “can't be stopped”.
8. **Multi-root** under `~/Documents/GitHub/khensu/`.
9. **Licences.** core Apache-2.0, specs CC BY 4.0, others AGPL-3.0.

## Install (short)

| Path | Steps |
| --- | --- |
| PWA | waves.khensu.nu → Share → Add to Home Screen |
| Sideload | `nu.waves.ipa` from khensu-apple Releases → Sideloadly / AltServer |
| Source | clone apple + core → `xcodegen generate` → scheme Waves or Ptah → Run |
| Hub | https://khensu.nu/app |

## Do not

- Hold site deploys for patents
- Make repos private by default
- Change desktop when only mobile was requested
- Phrase the network as unstoppable
- Add NXDOMAIN hosts to the shared products certificate
- Claim product-host HTTPS done from apex alone
- Leave NXDOMAIN / wrong-A certs on the proxy
- Wait for own-cert ACTIVE before attaching (deadlock)
