# <title>

| | |
|---|---|
| **Verdict** | Malicious / Suspicious / Benign |
| **Confidence** | High / Medium / Low |
| **Sample** | `sample.eml` |
| **Source** |  |
| **Analyzed** | YYYY-MM-DD |

**Summary** - <tl;dr>

---

## 1. Headers

| Field | Value |
|---|---|
| `From` (display) | |
| `From` (address) | |
| `Return-Path` | |
| `Reply-To` | |
| `Subject` | |
| `Date` | |
| `Message-ID` | |
| Originating IP | |
| Originating ASN / host | |

**Received chain** (earliest hop first):

```
<Received lines>
```

Observations - mismatches; hop count; geolocation vs claimed sender; inconsistencies

## 2. Authentication

| Mechanism | Result | Domain checked |
|---|---|---|
| SPF | | |
| DKIM | | |
| DMARC | | |

```
<Authentication-Results header>
```

Interpretation - 

## 3. Content

- Pretext and claimed sender
- Social engineering (urgency, authority, fear, reward)
- Greeting: targeted or generic
- Language, grammar, formatting quality; locale mismatches
- Branding: copied assets, remote-loaded images, tracking pixels
- Link text vs actual href
- Hidden text, invisible characters, or encoding used to evade filters

## 4. URLs

| # | URL (defanged) | Final destination | Notes |
|---|---|---|---|
| 1 | `hxxps://example[.]com/...` | | |

- Redirect chain
- Domain registration date and registrar
- Hosting / ASN
- Lookalike or homoglyph characteristics
- Landing page behavior
- Reputation: VirusTotal, URLhaus

## 5. Attachments

| Filename | Type | Size | SHA-256 |
|---|---|---|---|

- Static observations
- VirusTotal / MalwareBazaar results
- Behavior if detonated

## 6. Indicators of Compromise

```
Sender addresses:
Sender IPs:
Domains:
URLs:
File hashes:
```

## 7. MITRE ATT&CK

| Technique | ID | Where observed |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | <if a payload is delivered> |
| Phishing for Information: Spearphishing Link | T1598.003 | <if the lure solicits a response> |

## 8. Verdict and recommended response

**Verdict:** <malicious / suspicious / benign> - **<confidence>**

**Reasoning** - <evidence; and any limitation that bounds the verdict itself>

**Recommended actions**

1. Containment -
2. Scoping -
3. Identity -
4. Detection - <rules; expected FPs>
5. User communication -
   
## 9. Notes

**Limitations** - <e.g. landing page already offline at analysis time>
