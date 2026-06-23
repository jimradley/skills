# skills

A collection of [Claude Code](https://claude.com/claude-code) agent skills.

Each subdirectory is a self-contained skill (a `SKILL.md` plus any bundled
scripts/resources). To use one, place or symlink the skill directory into a
skills location Claude Code looks in (e.g. `~/.claude/skills/` or a project's
`.claude/skills/`).

## Skills

### `sensitive-info-scan`

Strictly scans a folder and its subfolders for things that shouldn't leak —
secrets, API keys, private keys, tokens, credentials, financial data (cards,
IBANs, sort codes), and personally identifiable information (emails, phone
numbers, UK National Insurance / NHS numbers, postcodes), plus GDPR
special-category data. Triggers on requests like "check for sensitive info",
"any secrets in here?", or "is this safe to push?".

It pairs a deterministic, dependency-free scanner (`scripts/scan.py` — regexes,
entropy checks, Luhn/checksum validation, "smart scope" that skips
vendor/build/VCS noise) with a contextual review pass that catches free-text
PII the patterns can't and triages false positives.

Run the scanner directly:

```bash
python sensitive-info-scan/scripts/scan.py <folder>
# options: --include-all (don't skip vendor dirs), --no-color, --max-bytes N
```

**Limitation:** it scans text only. Personal data inside images (e.g. photos of
receipts or documents) is skipped as binary and needs OCR/vision to inspect.
