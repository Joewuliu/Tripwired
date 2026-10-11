# Accuracy check

Run 2026-10-11 05:59 UTC on the deployed Phish Finder, 15 links, one at a time, through the same analyzer call a phone text uses. Scams are recent live phishing links; legit sites are well-known ones. Every address is defanged.

| # | Label | URL | Verdict | Score | Without blocklists | Top 2 signals | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | legit | `hxxps://www[.]wellsfargo[.]com` | No red flags found | 0 | No red flags found | Registered domain is official for Wells Fargo (brand list); Not listed by Google Safe Browsing, URLhaus or OpenPhish | 12.5 |
| 2 | legit | `hxxps://www[.]amazon[.]com` | No red flags found | 0 | No red flags found | Registered domain is official for Amazon (brand list); Not listed by Google Safe Browsing, URLhaus or OpenPhish | 11.4 |
| 3 | legit | `hxxps://www[.]unc[.]edu` | No red flags found | 0 | No red flags found | Domain is one of the 10,000 most visited on the web (Tranco list); Not listed by Google Safe Browsing, URLhaus or OpenPhish | 9.1 |
| 4 | legit | `hxxps://www[.]usps[.]com` | No red flags found | 0 | No red flags found | Registered domain is official for USPS (brand list); Not listed by Google Safe Browsing, URLhaus or OpenPhish | 11.9 |
| 5 | legit | `hxxps://www[.]apple[.]com` | No red flags found | 0 | No red flags found | Registered domain is official for Apple (brand list); Not listed by Google Safe Browsing, URLhaus or OpenPhish | 10.8 |
| 6 | scam | `hxxp://kxt8244z[.]demox[.]site/` | Dangerous | 95 | Suspicious | Listed as phishing by OpenPhish; Page names Adobe and asks for sensitive information (page text) | 12.5 |
| 7 | scam | `hxxps://sp1ct10-dorval-biz-zulzo-pelri[.]pages[.]dev/` | Dangerous | 130 | Dangerous | The hosting provider has already flagged this page as dangerous (Cloudflare phishing warning); Listed as phishing by OpenPhish | 9.0 |
| 8 | scam | `hxxps://voicemail[.]tsisd[.]ca/index[.]html` | Dangerous | 70 | Couldn't check | Listed as phishing by OpenPhish; The page did not load (browser) | 7.0 |
| 9 | scam | `hxxps://diskcacambasdetroit[.]com[.]br/auth/rackespace/` | Dangerous | 70 | No red flags found | Listed as phishing by OpenPhish; Page asks for a password (page scan) | 11.8 |
| 10 | scam | `hxxps://b592af96[.]click[.]kit-mail3[.]com/lmup7gdw6khmhn9nv4wu6h8wko4wkugh4ozgo/qvh8h7hdpek6edbl/aHR0cHM6Ly9kaXNrY2FjYW1iYXNkZXRyb2l0LmNvbS5ici9hdXRoL3JhY2tlc3BhY2U=/` | Dangerous | 70 | No red flags found | Listed as phishing by OpenPhish; Page asks for a password (page scan) | 9.8 |
| 11 | scam | `hxxp://120[.]84[.]212[.]206:35060/bin[.]sh` | Dangerous | 70 | Couldn't check | Listed as malware distribution by URLhaus; The page did not load (browser) | 7.4 |
| 12 | scam | `hxxp://42[.]231[.]65[.]187:33162/i` | Dangerous | 70 | Couldn't check | Listed as malware distribution by URLhaus; The page did not load (browser) | 7.6 |
| 13 | scam | `hxxp://151[.]234[.]36[.]221:38747/i` | Dangerous | 70 | Couldn't check | Listed as malware distribution by URLhaus; The page did not load (browser) | 17.2 |
| 14 | scam | `hxxp://125[.]45[.]67[.]66:58929/i` | Dangerous | 70 | Couldn't check | Listed as malware distribution by URLhaus; The page did not load (browser) | 7.5 |
| 15 | scam | `hxxp://124[.]6[.]169[.]54:60212/i` | Dangerous | 70 | Couldn't check | Listed as malware distribution by URLhaus; The page did not load (browser) | 7.6 |

- Scams flagged Dangerous or Suspicious: **10/10**
- Legit sites with "No red flags found": **5/5**
- Scams still flagged without blocklists: **2/10** (what the sandbox and the domain checks catch by themselves)
- Median time per check: **9.8 s**

## Notes

- Verdict and score come from the points table. Gemini only words the explanation: the analyzer has no per-request way to switch it off, so it stayed on. Answers worded by Gemini in this run: 6 of 15 (one call is attempted per scan when a key is set; a call that failed or was rejected leaves the plain wording and is not visible here).
- "Without blocklists" is computed from the same scan's evidence, not a second scan: threat-feed points are removed, a discount a listing had withheld is restored, and a brand named only in the address counts only if something else supports it. A popular site that was also listed is not given back its popularity discount.
- Scam links are recent: many are already gone when opened. Those show as Couldn't check, and a scam is caught then only through a feed listing or a brand in its address.
- Fresh scams requested: 10; got 10 from OpenPhish and URLhaus.
