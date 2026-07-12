# ShieldBox Lite

A phishing/scam link and email analyzer built for university students, inspired by a real phishing attack that targeted University of Calgary student inboxes in 2026.

## Phase 1: CLI URL Scanner (complete)

A command-line tool that analyzes a URL and returns a risk score (0-100), risk level (Low/Medium/High), and specific reasons for the score.

### Detection checks
- HTTPS presence
- URL length
- Presence of `@` symbol (redirect trick)
- Number of subdomains
- Number of hyphens
- Suspicious/urgency keywords
- Brand impersonation — checks for known brand names as substrings first (catches padded/disguised domains), then falls back to fuzzy string matching using `difflib.SequenceMatcher` to catch typosquatting variants (e.g. `rbcc.com` vs `rbc.com`)

### How to run
python cli/scanner.py

Paste a URL when prompted. Type `quit` to exit.

### Status
Phase 1 complete. Next: FastAPI backend (Phase 2), React frontend (Phase 3), email scanning (Phase 4), scan history dashboard (Phase 5).

## Limitations
Brand-impersonation detection currently uses a small, curated list of brands relevant to university-targeted phishing (banks, CRA, UCalgary/D2L), not a comprehensive database. A production version would use a continuously-updated domain reputation source, or an external API like Google Safe Browsing, instead.