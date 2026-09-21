# Leroy Merlin survey lure (Case 001)

| | |
|---|---|
| **Verdict** | Malicious |
| **Confidence** | High |
| **Sample** | `sample-1899.eml_` |
| **Source** | Phishing Pot |
| **Analyzed** | 2026-09-17 |

**Summary** - Fake promotional survey for a free item from Leroy Merlin. The attacker spoofed the `ml.tv-news.fr` domain. Contains three endpoints on stabrino[.]info, a survey link, a fake unsubscribe, and a hidden tracking pixel, which together track opens and clicks per recipient. No detailed information on the websites since it has been taken down. Mixes French and English, Kazakh hosting.

---

## 1. Headers

| Field | Value |
|---|---|
| `From` (display) | `Message de Leroy Merlin,` |
| `From` (address) | `programme_tv@ml.tv-news.fr.` and `programme_tv@ml.tv-news.fr` - malformed, two addresses, see observations |
| `Return-Path` | `programme_tv@ml.tv-news.fr` |
| `Reply-To` | None |
| `Subject` | `Nous avons une surprise pour les clients de Leroy Merlin.` |
| `Date` | `Sat, 11 Nov 2023 15:45:52 +0100` |
| `Message-ID` | `<SyvnJSL.0.0.SyvnJSL.9.SyvnJSL@ml.tv-news.fr>` |
| Originating IP | `89.46.34.187` |
| Originating ASN / host | `AS207333, Hoster.KZ (LLP "Kompaniya Hoster.KZ"), Kazakhstan. Abuse contact: hoster.kz. Netblock allocated 2023-05-08, six months before the message.` |

**Received chain** (earliest hop first):

```yaml
Received: from opuafauvct.pmaixspmorme.ptq (89.46.34.187) by
 MW2NAM12FT080.mail.protection.outlook.com (10.13.181.227) with Microsoft SMTP
 Server id 15.20.6977.10 via Frontend Transport; Sat, 11 Nov 2023 14:45:57
 +0000
Received-SPF: Fail (protection.outlook.com: domain of ml.tv-news.fr does not
 designate 89.46.34.187 as permitted sender) receiver=protection.outlook.com;
 client-ip=89.46.34.187; helo=opuafauvct.pmaixspmorme.ptq;
Authentication-Results: spf=fail (sender IP is 89.46.34.187)
 smtp.mailfrom=ml.tv-news.fr; dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=ml.tv-news.fr;compauth=fail
 reason=001
Received: from MW2NAM12FT080.eop-nam12.prod.protection.outlook.com
 (2603:10b6:a03:39c:cafe::d0) by SJ0PR03CA0351.outlook.office365.com
 (2603:10b6:a03:39c::26) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6977.26 via Frontend
 Transport; Sat, 11 Nov 2023 14:45:57 +0000
Received: from SJ0PR03CA0351.namprd03.prod.outlook.com (2603:10b6:a03:39c::26)
 by DM8P223MB0221.NAMP223.PROD.OUTLOOK.COM (2603:10b6:5:317::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6977.26; Sat, 11 Nov
 2023 14:45:58 +0000
Received: from DM8P223MB0221.NAMP223.PROD.OUTLOOK.COM (2603:10b6:5:317::21) by
 LV3P223MB0968.NAMP223.PROD.OUTLOOK.COM with HTTPS; Sat, 11 Nov 2023 14:45:59
 +0000
```

Observations -
- `From` contains a mangled address with a trailing dot, `programme_tv@ml.tv-news.fr.`, as well as the proper spoofed address, `programme_tv@ml.tv-news.fr`
- `From` display (`Message de Leroy Merlin`) and address (`programme_tv@ml.tv-news.fr`) do not match. The domain has no relationship to the brand named in the display name
- Domain of `ml.tv-news.fr` does not designate `89.46.34.187` as permitted sender
- No `Reply-To`
- `helo=opuafauvct.pmaixspmorme.ptq` is a randomly-generated-looking hostname on `.ptq`, which is not a registered TLD. Consistent with throwaway sending infrastructure rather than a legitimate mail server

## 2. Authentication

| Mechanism | Result | Domain checked |
|---|---|---|
| SPF | fail | `ml.tv-news.fr` |
| DKIM | none | n/a |
| DMARC | none | `ml.tv-news.fr (header.from)` |
| Sender ID (PRA) | fail | `ml.tv-news.fr` |

```
spf=fail (sender IP is 89.46.34.187)
 smtp.mailfrom=ml.tv-news.fr; dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=ml.tv-news.fr;compauth=fail
 reason=001
X-SID-PRA: PROGRAMME_TV@ML.TV-NEWS.FR
X-SID-Result: FAIL
X-MS-Exchange-Organization-PCL: 2
X-MS-Exchange-Organization-SCL: 9
```

**Microsoft EOP scores**

| Score | Value | Meaning |
|---|---|---|
| SCL (Spam Confidence Level) | 9 | Maximum on Microsoft's scale - classified as definite spam |
| PCL (Phish Confidence Level) | 2 | Low on Microsoft's 8-point scale - EOP's phishing-specific classifier was not confident this was phishing |

Interpretation - SPF fails because attacker's IP does not belong to the spoofed domain, there is no DKIM set, and because `ml.tv-news.fr` did not set up DMARC, the mail still gets delivered instead of rejected. Microsoft's composite authentication also returned `compauth=fail reason=001`. Their own stack concluded the sender was not authentic, and the message was delivered regardless, because the spoofed domain published no DMARC policy to enforce against. Sender ID (PRA) also fails against the same domain, an independent legacy check from SPF/DKIM/DMARC. Microsoft's own spam and phish classifiers disagree here - SCL rates it maximum-confidence spam, PCL rates phishing-confidence low - which reflects that they score different things, not a contradiction in the evidence; the authentication failures and brand/domain mismatch above are stronger signal than either score alone.

## 3. Content

- Claims to be Leroy Merlin (French home improvement retailer), sent from ml.tv-news.fr which has no relationship to the brand, offering a free screwdriver set for completing a survey
- Social engineering levers: Reward = the free tool `Nous aimerions vous offrir une opportunité unique de recevoir une toute nouvelle Jeu de tournevis Wiha!`. Urgency = the same-day expiry `Cette offre d'enquête expire aujourd'hui`
- Generic greeting: `Cher acheteur Leroy Merlin,`, consistent with bulk sending rather than a targeted message
- Mix of languages: French = Reward promise. English = Unsubscribe text
- Branding: Remote images on Imgur, not sender infrastructure, which is abuse of a reputable service to dodge domain blocklisting. Plus the broken relative-path CSS background (`./images/bgasdfasdfa.jpg`), which shows the markup was written for a web page.
- Hidden text / encoding: a 1×1 pixel image with visibility:hidden loads from hxxp://stabrino[.]info/op/... - a tracking pixel that reports message open, IP and client without any click.

## 4. URLs

| # | URL (defanged) | Final destination | Notes |
|---|---|---|---|
| 1 | `hxxps://imgur[.]com/FZplvp9[.]png` | - | Hosted Image |
| 2 | `hxxps://imgur[.]com/VlsGZrQ[.]png` | - | Hosted Image |
| 3 | `hxxp://stabrino[.]info/cl/5433_md/1995/978/2024/222/428764` | Inactive | Survey CTA ("Start Survey"), click tracking |
| 4 | `hxxp://stabrino[.]info/oop/5433_md/1995/978/2024/222/428764` | Inactive | Fake unsubscribe ("here"), opt-out tracking |
| 5 | `hxxp://stabrino[.]info/op/5433_md/1995/978/2024/222/428764` | Inactive | 1x1 hidden tracking pixel, open tracking |

stabrino[.]info: DomainTools = deleted/available; who.is: registered but inactive, domain no longer resolves (no DNS, no cert); urlscan unreachable at time of analysis; no VirusTotal detections; not listed on URLhaus. DomainTools' historical record showed 29 IP changes, all to distinct addresses, and 8 nameserver changes over roughly 3 years (close to one IP change per month on average). The exact IP list and change dates were not retrievable at time of writing, and this history reflects the domain's behavior after the campaign (Nov 2023) up to the point of lookup, not necessarily during it. Still, that level of churn is consistent with infrastructure that gets rehosted repeatedly to dodge blocklisting, though cheap or abused shared hosting can produce similar churn without deliberate evasion.

## 5. Attachments

None

## 6. Indicators of Compromise

```
Sender addresses: programme_tv@ml.tv-news.fr
Sender IPs: 89.46.34.187
Domains: ml.tv-news.fr (Spoofed, not attacker owned)
Other indicators: HELO string opuafauvct.pmaixspmorme[.]ptq (non-standard/invalid TLD, throwaway hostname)
URLs:  hxxps://imgur[.]com/FZplvp9[.]png; hxxps://imgur[.]com/VlsGZrQ[.]png; hxxp://stabrino[.]info/cl/5433_md/1995/978/2024/222/428764; hxxp://stabrino[.]info/oop/5433_md/1995/978/2024/222/428764; hxxp://stabrino[.]info/op/5433_md/1995/978/2024/222/428764
File hashes: None
```

## 7. MITRE ATT&CK

| Technique | ID | Where observed |
|---|---|---|
| Phishing for Information: Spearphishing Link | T1598.003 | `Start Survey link` -> `stabrino[.]info/cl/...`; survey lure solicits a response, no payload or attachment present |

## 8. Verdict and recommended response

**Verdict:** Malicious - **High**

**Reasoning:** 
- The domain is spoofed (SPF fail, no DKIM) and the displayed brand has no connection to the sending domain. The prize lure with same-day expiry, three tracking endpoints sharing a per-recipient ID, and Kazakh hosting for a French-language lure impersonating a French retailer all point the same way. Microsoft's own SCL score (9, maximum) agrees; its lower PCL score (2) reflects the phish-specific classifier's uncertainty, not a competing verdict - see Section 2. `stabrino[.]info`'s DomainTools history also shows heavy churn (29 IP changes, 8 nameserver changes over ~3 years) - supporting evidence of persistently-abused infrastructure, though that history postdates the campaign and its exact timeline was not retrievable at time of writing (see Section 4).
- VirusTotal shows no detections, but absence isn't evidence of benign, it's consistent with a low volume or abandoned domain.
- Counter-evidence: a List-Unsubscribe header is present, which is legitimate bulk-mail behavior. Rejected because the unsubscribe URL is attacker infrastructure functioning as a tracking endpoint
- The landing page was unreachable, so the final objective is unconfirmed, but the verdict is not.

**Recommended actions**

1. Block sender IP 89.46.34.187 at the mail gateway; block stabrino[.]info at web proxy and DNS. Quarantine inbound mail claiming ml.tv-news.fr that fails SPF. Do not completely block the domain, it belongs to a spoofed third party.
2. Purge from all mailboxes that received it; search mail logs for the sender IP and the stabrino[.]info URLs.
3. If anyone submitted the survey, treat as credential/PII exposure: reset, revoke sessions, check sign-in logs.
4. Detection - HELO hostname on a non-existent TLD; low FP, allowlist misconfigured internal senders once. SPF fail + brand in the display name mismatching the envelope domain is the weaker option, it over-fires on ESPs sending for brands. Add IOCs to blocklists; report the Imgur URLs for takedown.
5. Notify recipients

## 9. Notes

- Triple endpoint (`/cl/`, `/oop/` and `/op/`) on the same host with an identical trailing ID: click, opt-out, open. All three confirm the address is live
- stabrino[.]info shares a TLS certificate with ~45 unrelated domains, including cdscount[.]pro, a lookalike for the French retailer Cdiscount. Shared certificates are also normal on cheap hosting, so this shows shared infrastructure rather than the same owner.
- Mapped to T1598.003 rather than T1566.002: the message carries no attachment or executable content, and the lure solicits a response rather than delivering code. Since the landing page was unreachable, the final objective is unconfirmed. If it served malware rather than a form, T1566.002 would be the correct mapping instead.

**Limitations**
- Sample from a public repository, so no recipient-side telemetry, proxy logs or click-through data were available.
- Endpoints on `stabrino[.]info` were already offline at analysis time; the destination is assessed from passive sources only.
- urlscan unreachable at time of analysis.
- DomainTools reported 29 IP changes and 8 nameserver changes, but the exact addresses and dates were not retrievable, and that history postdates the campaign.