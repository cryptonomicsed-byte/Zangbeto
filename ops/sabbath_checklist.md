# Sabbath Seal — Weekly Ritual

1. **Collect**: Run listener logs and n8n outputs.
2. **Filter**: Deduplicate by fingerprint; discard noise.
3. **Attest**: Call `attest_verified` for true findings; `mark_disputed` or `accept_risk` otherwise.
4. **Patch**: Land fixes; reference commit hash in off-chain receipt JSON.
5. **Anchor**: Upload weekly summary to Arweave; note txid in change log.
6. **Rotate**: Backup cursors, rotate secrets if needed, review witness set.
7. **Seal**: Publish a brief "Sabbath Seal" note for the week.

---

## Notes

- Ensure Clock access for time-bounded calls.
- Verify 0x2:: imports for your Sui rev.
- Evidence hash must be 32 bytes (SHA-256).

---

## Structured Diagnostics

- Verify diagnostic codes follow `OMO-ERR-XXX` format.
- Check category values: type(1), logic(2), security(4), receipt(8), identity(16), rhythm(32).
- Validate severity: info(0), warning(1), error(2).
- Confirm repair_strategy: auto(1), manual(2), hybrid(3).
- Verify Zangbeto signature on critical diagnostics before processing.
- Check that message_hash is SHA-256 of the full human-readable message.
