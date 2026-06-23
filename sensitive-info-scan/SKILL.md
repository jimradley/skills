---
name: sensitive-info-scan
description: >-
  Scan a folder and its subfolders for sensitive data — secrets, API keys,
  credentials, private keys, tokens, connection strings, financial details
  (card numbers, IBANs, sort codes), and personally identifiable information
  (emails, phone numbers, UK National Insurance / NHS numbers, postcodes,
  names, addresses) plus GDPR special-category data (health, ethnicity,
  religion, etc.). Use this whenever the user asks to check, scan, audit, or
  review a directory, repository, or project for sensitive info, secrets, API
  keys, passwords, credentials, leaked keys, PII, personal or customer data,
  GDPR / data-protection concerns, or whether something is safe to commit,
  push, publish, share, or open-source — even if they don't say the exact
  words "sensitive info". Triggers on phrases like "check for sensitive info",
  "any secrets in here?", "is this safe to push?", "scan for API keys",
  "do a GDPR check", "find any PII", or "anything personal in this folder".
---

# Sensitive-info scan

Find data that should not be exposed before a folder gets committed, pushed,
shared, or published. The guiding instinct is **strict**: a missed live API
key or a customer's medical record is far more costly than a false positive,
so when in doubt, surface it and label it for review rather than dropping it.

The job has two halves that complement each other:

1. A bundled scanner (`scripts/scan.py`) does the **deterministic** work —
   regexes, entropy checks, Luhn/checksum validation. This is fast and
   reliable for anything with structure (keys, card numbers, NI/NHS numbers).
2. You add the **contextual** judgement a regex can't: spotting a person's
   full name next to their address in prose, recognising that `AKIA…EXAMPLE`
   is the well-known AWS docs placeholder, or that `4242 4242 4242 4242` is a
   public Stripe test card. This is the part only a reader can do.

The output is a simple on-screen list — don't write report files unless asked.

## Step 1 — Pick the target

Scan the folder the user named. If they didn't name one, scan the current
working directory and say so. If it's ambiguous (e.g. they're mid-project with
several folders open), ask which folder before scanning rather than guessing.

## Step 2 — Run the scanner

```bash
python <skill-dir>/scripts/scan.py "<folder>"
```

It walks the tree and prints findings grouped by severity, redacting the
matched values. Under "smart scope" it skips dependency/build/VCS noise
(`node_modules`, `.git`, `bin`, `obj`, `.venv`, `dist`, …), minified assets,
and lock files — those are full of third-party sample keys that drown out real
findings. Useful flags:

- `--include-all` — also scan the skipped vendor/build dirs (use if the user
  suspects a secret was committed *inside* `node_modules` or similar).
- `--no-color` — plain output (for logs / redirected output).

What it detects deterministically: private keys; AWS / Google / GitHub / Slack
/ Stripe / OpenAI / Anthropic keys; credentials embedded in URLs; JWTs; bearer
tokens; generic high-entropy `secret=…` assignments; credit/debit cards
(Luhn-checked); IBANs; UK NI numbers; UK NHS numbers (checksum-checked);
emails; UK mobile numbers; sort codes; postcodes; public IPs; and
secret-bearing filenames (`.env`, `id_rsa`, `credentials.json`, …).

## Step 3 — Read, don't just run

The scanner is a sieve, not the verdict. Open the flagged files, and also skim
the text files it had nothing to say about (READMEs, docs, notes, CSV/JSON
data, config). Two goals:

**Catch what patterns miss.** Regexes can't recognise free-text PII. Look for
things like:
- A real person's full name together with a postal address, date of birth, or
  other identifying detail.
- Health, sexual-orientation, religious, ethnic, political, or criminal-record
  information written as prose (GDPR special-category data — high sensitivity).
- Financial or account details described in words rather than as a card number.
- Internal hostnames, employee lists, or anything clearly confidential.

**Triage false positives.** Annotate, don't silently drop:
- Obvious placeholders the scanner already skipped, and any it didn't
  (`AKIAIOSFODNN7EXAMPLE`, `sk_test_…`, `your-key-here`).
- Public test fixtures (Stripe's `4242…` card, example NHS numbers in test data).
- Values that are clearly sample/fake from surrounding context.

When you downgrade something, say *why* — the user needs to trust the triage.
If you're unsure whether something is real, keep it and mark it for review;
strictness beats a tidy-looking miss.

## Step 4 — Present the list

Show a console list grouped by severity, building on the scanner's output and
folding in what your review added or reclassified. Keep secret values
redacted (the scanner already does this — don't paste full keys back). Then
close with:

- **A one-line risk summary** — e.g. "3 live-looking secrets and customer PII
  for 3 people; not safe to commit as-is."
- **Recommended actions**, matched to what was found: remove and **rotate**
  any exposed secret (rotation matters — a key that's been committed is
  compromised even after deletion), add sensitive files to `.gitignore`,
  move PII out of the repo or redact it, and hold off committing/publishing
  until resolved.

## Severity guide

- **CRITICAL** — live credentials and direct financial identifiers: private
  keys, real API keys, passwords, credentials in URLs, card numbers.
- **HIGH** — strong PII and likely-real secrets: NI/NHS numbers, IBANs, JWTs,
  bearer tokens, `.env`/credential files, high-entropy secret assignments.
- **MEDIUM** — contact-level PII: emails, phone numbers, sort codes, postcodes.
- **REVIEW** — context-dependent: public IPs, GDPR-keyword hits, and anything
  you weren't sure about. Worth a human glance, not necessarily a problem.
