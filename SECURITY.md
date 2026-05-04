# Security Notes

This is a static-site hardening setup for GitHub Pages.

## Threat model

Protected against casual browsing of plaintext learning data in a public repository.

Not protected against:

- weak passwords
- sharing the password publicly
- putting plaintext JSON in the repository
- browser/device compromise
- determined offline brute force if the password is weak

## Rules

1. Do not commit plaintext `keywords.json` or `relations.json`.
2. Use a long unique passphrase.
3. Do not include patient information, school-identifiable private data, or personal secrets.
4. Rotate the passphrase by re-encrypting `data/encrypted-data.json` when needed.
