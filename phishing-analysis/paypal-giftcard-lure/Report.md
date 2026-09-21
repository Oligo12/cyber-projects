# PayPal gift card lure (Case 002)

| | |
|---|---|
| **Verdict** | Malicious |
| **Confidence** | High |
| **Sample** | `sample-1870.eml_` |
| **Source** | Phishing Pot |
| **Analyzed** | 2026-09-17 |

**Summary** - Fake Black Friday reward promising a €1000 PayPal gift card, sent from the abused `my.esprit-friends.com` domain via Romanian VPS hosting (SPF/DKIM/DMARC fail). Reply-To points to a separate VT-flagged malicious domain, `firiri.shop`, and stray `Otto.de` branding leaks in the Message-ID - four inconsistent domains in total. The "Jetzt Teilnehmen" CTA is wrapped in a `t.co` (X/Twitter) shortlink abused to redirect to `innovataq[.]com`; separately, `myhealthyliving[.]life` hosts two fake-unsubscribe links and a hidden tracking pixel that track opens and clicks per recipient. No detailed information on `innovataq[.]com` or `myhealthyliving[.]life` since both are now inactive. Mixes German and English.

---

## 1. Headers

| Field | Value |
|---|---|
| `From` (display) | `"PayPal 💸🤑", "PayPal 💸🤑"` |
| `From` (address) | `news@my.esprit-friends.com` |
| `Return-Path` | `news@my.esprit-friends.com` |
| `Reply-To` | `reply_to@firiri.shop` |
| `Subject` | `Glückwunsch! Jetzt Gewinndaten eintragen 🌟🎉🎊` |
| `Date` | `Fri, 10 Nov 2023 02:55:41 +0100` |
| `Message-ID` | `<GMXEGIK.89993.025+=phishing@pot@service@newsletter.otto.de>` |
| Originating IP | `80.96.157.110` |
| Originating ASN / host | `AS9009 (M247 Europe SRL) announcing 80.96.157.0/24; address space assigned to Virtono Networks SRL, Constanța, Romania - a VPS provider. Assignment created 2022-06-27, roughly 16 months before the message. Abuse contacts: @virtono.com (route object), @rnc.ro (parent netblock).` |

**Received chain** (earliest hop first):

```yaml
Received: from k2k3gqsqbcj9zvo937u9qlskihyci1gg.c5giy (80.96.157.110) by
 VI1EUR05FT005.mail.protection.outlook.com (10.233.242.124) with Microsoft
 SMTP Server id 15.20.6977.21 via Frontend Transport; Fri, 10 Nov 2023
 01:56:55 +0000
Received-SPF: Fail (protection.outlook.com: domain of my.esprit-friends.com
 does not designate 80.96.157.110 as permitted sender)
 receiver=protection.outlook.com; client-ip=80.96.157.110;
 helo=k2k3gqsqbcj9zvo937u9qlskihyci1gg.c5giy;
Authentication-Results: spf=fail (sender IP is 80.96.157.110)
 smtp.mailfrom=my.esprit-friends.com; dkim=none (message not signed)
 header.d=none;dmarc=none action=none
 header.from=my.esprit-friends.com;compauth=fail reason=001
Received: from VI1EUR05FT005.eop-eur05.prod.protection.outlook.com
 (2603:10a6:d10:97:cafe::c3) by FR0P281CA0131.outlook.office365.com
 (2603:10a6:d10:97::16) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6977.19 via Frontend
 Transport; Fri, 10 Nov 2023 01:56:55 +0000
Received: from FR0P281CA0131.DEUP281.PROD.OUTLOOK.COM (2603:10a6:d10:97::16)
 by SJ1P223MB0434.NAMP223.PROD.OUTLOOK.COM (2603:10b6:a03:45f::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6954.28; Fri, 10 Nov
 2023 01:56:57 +0000
Received: from SJ1P223MB0434.NAMP223.PROD.OUTLOOK.COM (2603:10b6:a03:45f::13)
 by LV3P223MB0968.NAMP223.PROD.OUTLOOK.COM with HTTPS; Fri, 10 Nov 2023
 01:56:58 +0000
```

Observations -
- Display, address, and Reply-To mismatch; domain/brand inconsistency across four distinct hostnames: Display name = `PayPal`, sending domain = `my.esprit-friends.com`, Message-ID = `newsletter.otto.de`, Reply-To = `firiri.shop`
- `helo=k2k3gqsqbcj9zvo937u9qlskihyci1gg.c5giy` is a randomly-generated-looking hostname on `.c5giy`, which is not a registered TLD. Consistent with throwaway sending infrastructure rather than a legitimate mail server

## 2. Authentication

| Mechanism | Result | Domain checked |
|---|---|---|
| SPF | fail | `my.esprit-friends.com` |
| DKIM | none | n/a |
| DMARC | none | `my.esprit-friends.com` |
| Sender ID (PRA) | fail | `NEWS@MY.ESPRIT-FRIENDS.COM` |

```
spf=fail (sender IP is 80.96.157.110)
 smtp.mailfrom=my.esprit-friends.com; dkim=none (message not signed)
 header.d=none;dmarc=none action=none
 header.from=my.esprit-friends.com;compauth=fail reason=001
X-SID-PRA: NEWS@MY.ESPRIT-FRIENDS.COM
X-SID-Result: FAIL
X-MS-Exchange-Organization-PCL: 4
X-MS-Exchange-Organization-SCL: 5
```

**Microsoft EOP scores**

| Score | Value | Meaning |
|---|---|---|
| SCL (Spam Confidence Level) | 5 | Spam Suspected on Microsoft's scale - sent to Junk |
| PCL (Phish Confidence Level) | 4 | Suspicious on Microsoft's 8-point scale |

Interpretation - SPF fails because attacker's IP does not belong to the spoofed domain, there is no DKIM set, and because `my.esprit-friends.com` did not set up DMARC, the mail still gets delivered instead of rejected. Microsoft's composite authentication also returned `compauth=fail reason=001`. Their own stack concluded the sender was not authentic, and the message was delivered regardless, because the spoofed domain published no DMARC policy to enforce against. Sender ID (PRA) also fails against the same domain, an independent legacy check from SPF/DKIM/DMARC. Microsoft's own spam and phish agree here - SCL rates it as "Spam Suspected", PCL rates phishing-confidence as "Suspicious".

## 3. Content

- Claims to be PayPal, sent from `my.esprit-friends.com` which has no relationship to the brand, offering a 1000€ PayPal ticket for "participating in a Black Friday campaign"
- Social engineering levers: Reward = free money `Diese 1000€ PayPal Karte könnte Ihnen gehören.`
- Greeting: Personalized via mail-merge field - `Hallo phishing@pot,` shows the template inserts the recipient address itself; in this sample that field happens to be populated with the Phishing Pot placeholder address rather than a real name
- Mix of languages: German = Reward promise. English = Unsubscribe text
- Placeholder URLs, signifying premade template usage: `hxxps://1.2.3`
- Shortened redirection URL `hxxps://t[.]co/147gpL3Pb2` leading to `hxxps://innovataq[.]com/1013baa9f7dbb929800`. `innovataq[.]com` shows as unregistered on whois.com
- Several URLs with encoded paths, see `4. URLs` for more information
- Hidden text / encoding: a 1×1 pixel image with visibility:hidden loads from hxxp://myhealthyliving.life/VGZQQ... - a tracking pixel that reports message open, IP and client without any click.

## 4. URLs

| # | URL (defanged) | Final destination | Notes |
|---|---|---|---|
| 1 | `hxxps://1.2.3` | - | Template Placeholder |
| 2 | `hxxps://t[.]co/147gpL3Pb2` | `hxxps://innovataq[.]com/1013baa9f7dbb929800` | Primary CTA - wraps the "» Jetzt Teilnehmen «" (Participate Now) button, the actual link a victim clicks to claim the fake reward |
| 3 | `hxxp://myhealthyliving[.]life/VG9STktYWWF2L2h6d0c3YTVjNlNjdWtWUk9QczRHNkk3b1pPZzBEUGJqOElYZWZyUVRBRTB0V0gvMjB4VTl6TTMzVmFIQmVzaUp6Nk93ZUJrd2xWS1E9PQ__` | Inactive | Fake unsubscribe 1 ("Hier" link mid-body), opt-out tracking |
| 4 | `hxxp://myhealthyliving[.]life/OFBPUnRTNGZNd2pabEpxZDB6K0dUZ1RtV1M3T3N4NU5Sb2xtWW95MTZmNStjSkZrc05oYjZtY3ZHRW00Y1RPdVV1YVA1SW9vY0xXTmJKbWhPQnJaQlE9PQ__` | Inactive | Fake unsubscribe 2 ("here" link in footer), opt-out tracking |
| 5 | `hxxp://myhealthyliving[.]life/VGZQQVNTSGN5RTU2cFZ5cUJaUXN1WWJyZFRYNVEyWGdBMDZtazg3dU93UUpCVG15ak5kM3IySmFDZDRadnZucDVxUm1pY2h5TEZaR3E4V0ZKOWhSb0E9PQ__` | Inactive | 1x1 hidden tracking pixel, open tracking |
| 6 | `hxxps://imgur[.]com/1ganv65[.]jpg` | - | Hosted header image |

hxxp://myhealthyliving[.]life: DomainTools = not registered; who.is: not registered; urlscan unreachable at time of analysis; no VirusTotal detections; not listed on URLhaus. DomainTools' historical record showed 18 IP changes, all to distinct addresses, and 16 nameserver changes over roughly 9 years. The exact IP list and change dates were not retrievable at time of writing.

## 5. Attachments

None

## 6. Indicators of Compromise

```
Sender addresses: news@my.esprit-friends.com
Sender IPs: 80.96.157.110
Domains: my.esprit-friends.com (abused send domain, SPF fail), firiri.shop (Reply-To, VT-flagged malicious - treat as attacker-owned, not just spoofed), newsletter.otto.de (appears only inside the Message-ID string; likely template boilerplate, never shown to the recipient)
Other indicators: HELO string k2k3gqsqbcj9zvo937u9qlskihyci1gg[.]c5giy (non-standard/invalid TLD, throwaway hostname)
URLs: hxxps://1.2.3; hxxps://t[.]co/147gpL3Pb2; hxxps://innovataq[.]com/1013baa9f7dbb929800; hxxp://myhealthyliving[.]life/VG9STktYWWF2L2h6d0c3YTVjNlNjdWtWUk9QczRHNkk3b1pPZzBEUGJqOElYZWZyUVRBRTB0V0gvMjB4VTl6TTMzVmFIQmVzaUp6Nk93ZUJrd2xWS1E9PQ__; hxxp://myhealthyliving[.]life/OFBPUnRTNGZNd2pabEpxZDB6K0dUZ1RtV1M3T3N4NU5Sb2xtWW95MTZmNStjSkZrc05oYjZtY3ZHRW00Y1RPdVV1YVA1SW9vY0xXTmJKbWhPQnJaQlE9PQ__; hxxp://myhealthyliving[.]life/VGZQQVNTSGN5RTU2cFZ5cUJaUXN1WWJyZFRYNVEyWGdBMDZtazg3dU93UUpCVG15ak5kM3IySmFDZDRadnZucDVxUm1pY2h5TEZaR3E4V0ZKOWhSb0E9PQ__; hxxps://imgur[.]com/1ganv65[.]jpg
File hashes: None
```

## 7. MITRE ATT&CK

| Technique | ID | Where observed |
|---|---|---|
| Phishing for Information: Spearphishing Link | T1598.003 | "Jetzt Teilnehmen" CTA -> `hxxps://t[.]co/147gpL3Pb2` -> `hxxps://innovataq[.]com/1013baa9f7dbb929800`; prize-claim lure solicits a response, no payload or attachment present |

## 8. Verdict and recommended response

**Verdict:** Malicious - **High**

**Reasoning:** 
- The domain is spoofed (SPF fail, no DKIM) and the displayed brand has no connection to the sending domain. The cash-prize lure, the CTA disguised behind a `t.co` shortlink, and three separate tracking endpoints on `myhealthyliving[.]life` (two fake-unsubscribe links plus a pixel, each carrying its own distinct token - see Section 9) all point the same way. Microsoft's own SCL score (5, Spam Suspected) agrees, as well as the PCL score (4, Suspicious)
- VirusTotal shows no detections for `myhealthyliving[.]life`, but flags `firiri[.]shop` as malicious
- The landing page was unreachable, so the final objective is unconfirmed, but the verdict is not.

**Recommended actions**

1. Block sender IP 80.96.157.110 at the mail gateway; block `myhealthyliving[.]life` and `innovataq[.]com` at web proxy and DNS. Quarantine inbound mail claiming `my.esprit-friends[.]com` that fails SPF - don't fully block that domain, it appears to be an abused legitimate third party. `firiri[.]shop` is VT-flagged malicious and only appears as Reply-To, so it can be blocked outright rather than handled as a spoofed victim domain.
2. Purge from all mailboxes that received it; search mail logs for the sender IP and the `myhealthyliving[.]life` and `innovataq[.]com` URLs.
3. If anyone completed the "Jetzt Teilnehmen" flow, treat as credential/PII exposure: reset, revoke sessions, check sign-in logs.
4. Detection - HELO hostname on a non-existent TLD; low FP, allowlist misconfigured internal senders once. Shortener-wrapped CTA from a first-seen sender domain is too noisy alone, only usable alongside the SPF failure. Add IOCs to blocklists; report the Imgur URLs for takedown.
5. Notify recipients

## 9. Notes

- Two fake-unsubscribe links plus the tracking pixel share the `myhealthyliving.life` host, but unlike Case 001 they do NOT share a common trailing ID - each path decodes (base64-of-base64) to a distinct 64-byte opaque token, most likely a per-link or per-recipient identifier rather than one shared campaign ID. All three still confirm the address is live.
- Mapped to T1598.003 rather than T1566.002: the message carries no attachment or executable content, and the lure solicits a response rather than delivering code. Since the landing page was unreachable, the final objective is unconfirmed. If it served malware rather than a form, T1566.002 would be the correct mapping instead.

**Limitations**
- Sample from a public repository, so no recipient-side telemetry, proxy logs or click-through data were available.
- `innovataq[.]com` and `myhealthyliving[.]life` were both inactive at analysis time; the destination is assessed from passive sources only.
- urlscan unreachable at time of analysis.
- DomainTools reported 18 IP changes and 16 nameserver changes over roughly 9 years, but the exact addresses and dates were not retrievable.
- RDAP shows registration beginning 2024-06-11, seven months after the campaign, so that record may not reflect the registrant active at send time.
