# Phishing Analysis
**Author:** Nikola Marković  
**Status:** ongoing  
**Last updated:** 2026-09-21  
**Repo:** https://github.com/Oligo12/cyber-projects/  
**Email:** nikola.z.markovic@pm.me  
**LinkedIn:** https://www.linkedin.com/in/nikolazmarkovic/  

[Back to Main README](../README.md)

Triage of real phishing emails: header and `Received` chain analysis, SPF/DKIM/DMARC verdict, URL and infrastructure assessment, IOC extraction, and a written verdict with recommended actions. The verdict and actions are what an L1 hands over in a ticket queue. The writeup goes further than queue time allows.

Payload-side reverse engineering is out of scope here and is covered in [**malware-analysis**](../malware-analysis).

**Scope note:** both published cases are prize and survey lures delivered by link (T1598.003), taken from a public collection of real phishing emails with the landing infrastructure already offline, so the final objective is documented as unconfirmed in each. An attachment-based case following delivery through to payload execution is in progress.

---

## Cases

| Case | Lure | Verdict | Key findings |
|---|---|---|---|
| [leroy-merlin-survey-lure](./leroy-merlin-survey-lure/) | Free prize for completing a survey (FR) | Malicious, high | Spoofed `ml.tv-news.fr` (SPF fail, no DKIM, no DMARC), Kazakh hosting for a French-language retail lure, three tracking endpoints sharing one per-recipient ID, Imgur-hosted branding |
| [paypal-giftcard-lure](./paypal-giftcard-lure/) | €1000 gift card, Black Friday (DE) | Malicious, high | Abused `my.esprit-friends.com`, CTA wrapped in a `t.co` shortlink, VT-flagged `firiri.shop` as `Reply-To`, four inconsistent domains across `From` / `Reply-To` / `Message-ID` |
| *attachment-based case* | *Attachment* | *in progress* | *delivery through to payload* |

---

## Patterns across cases

Both samples predate analysis by roughly three years and come from the same sample source, so this is not a campaign link. What repeats is the tradecraft:

- **Invalid-TLD HELO.** Both connected with a randomly generated hostname on a TLD that does not exist (`.ptq`, `.c5giy`). This is a strong signal in either case and the cheapest to detect.
- **Missing DMARC does the work, not the spoof.** Both failed SPF and had no DKIM, and both were delivered anyway because the impersonated domain published no DMARC policy to enforce against. Microsoft's composite authentication returned `compauth=fail` in both and the mail still landed.
- **Tracking triad.** Both carried a click endpoint, a fake unsubscribe, and a hidden 1x1 pixel on attacker infrastructure. The fake unsubscribe is the notable one: it reads as legitimate bulk-mail behavior and functions as confirmation that the address is live. They differ in how they identify the recipient, one shared trailing ID versus distinct per-link tokens.
- **Reputable services as cover.** Imgur for branding images in both, and a `t.co` shortlink in the second, so the reputationally weak domain never appears in the visible link.
- **Language mismatch.** Lure text localized (French, German), unsubscribe boilerplate left in English. A template artifact, and a usable tell.
- **Reputation feeds were silent.** No VirusTotal detections and no URLhaus listing for the primary infrastructure in either case.

---

## Triage workflow

1. **Preserve the original.** Work from the raw `.eml` with full headers, never a forwarded copy, which rewrites headers and destroys the evidence.
2. **Header and `Received` chain.** Read the chain to reconstruct the true path. Compare `Return-Path`, `From` address, `From` display name and `Reply-To` against each other, and check the HELO hostname for throwaway or invalid-TLD patterns.
3. **Authentication verdict.** SPF, DKIM and DMARC, verified against the sending domain's records rather than trusted as reported, plus any platform scores present and what they do and do not mean.
4. **Content and lure.** Pretext, social engineering lever, targeting, branding source, and any hidden or encoded content.
5. **URL and infrastructure.** Defang, unwrap shorteners and redirectors, resolve the destination, check registration age, hosting and reputation. Interaction with live infrastructure happens only from the isolated lab.
6. **Attachments.** Hash and identify by structure, not extension. Detonation, where warranted, happens in the [malware-analysis](../malware-analysis) lab.
7. **IOC extraction.** Senders, sending IPs, domains, URLs, hashes, and distinctive header artifacts such as HELO strings.
8. **Verdict and response.** Malicious, suspicious or benign, with the evidence, and actions split into containment, scoping, identity, detection and user communication.

---

## On verdicts

Three things I hold to for triage:

- **Counter-evidence is raised and answered.** Where something points toward legitimacy, it is stated and then addressed.
- **Limitations bound the claim.** Where the landing page was gone or a record was unretrievable, the report says so, as well as how it does or doesn't affect the verdict.
- **Detection ideas carry their false positives.** A rule without a statement of what it over-fires on is not a usable rule.

---

## Phishing taxonomy (reference)

The cases here are link-based information solicitation, the second row. The rest is reference.

| Type | Delivery | What makes it hard to catch |
|---|---|---|
| **Credential harvesting** | Link to a fake login page | Lookalike domains, legitimate hosting with valid TLS, link-protection rewrites hiding the destination |
| **Information solicitation** | Survey, prize or reply-based lure | Often no payload and sometimes no credential theft, so content scanning has little to bite on |
| **Malware delivery** | Attachment or link to payload | Password-protected archives defeat scanning, macro and LNK lures, HTML smuggling |
| **BEC / CEO fraud** | Plain text, no payload | No link or attachment at all. Detection depends on sender and behavioral anomalies |
| **Compromised account** | Internal sender, real mailbox | Passes SPF, DKIM and DMARC legitimately, because it is the real sender. Thread hijacking makes it plausible |
| **QR code (quishing)** | Image containing a QR code | The URL sits inside an image, so URL scanning misses it, and the user moves to a personal phone outside corporate controls |
| **OAuth consent** | Link to a genuine Microsoft or Google consent screen | No password stolen and none to reset. The attacker receives a token through a legitimate consent flow, and MFA does not stop it |

---

## Environment and sources

- Samples: [Phishing Pot](https://github.com/rf-peixoto/phishing_pot), a public repository of real phishing mail
- Header and static inspection: analyst workstation, no interaction with attacker infrastructure
- Any live URL interaction or detonation: isolated lab VM with controlled egress
- Enrichment: VirusTotal, URLhaus, urlscan, DomainTools, RDAP/whois

**Safety notes.** All URLs and indicators are defanged. Raw `.eml` samples are not committed to this repository; each case cites its source filename so the analysis is reproducible. No credentials, real or fabricated, are ever submitted to a phishing page, since submission confirms the address is live to the operator.
