# Lean SAST ruleset (gate 4)

Small, pinned, in-repo Opengrep ruleset for the lean 6-gate charter. Run in CI by
`.github/workflows/quality.yml` -> `reusable-quality.yml`:

```
opengrep scan --config .quality/opengrep --error .
```

The gate is clean-zero: any ERROR-severity match fails CI. Rules are an
opengrep/semgrep-compatible curated subset of `p/python` and
`p/r2c-security-audit`, scoped to the security patterns that actually matter for
this pure-Python project (command injection, unsafe deserialization, weak
crypto, disabled TLS verification, committed private keys/cloud keys).

Files:

- `python-security.yaml` — Python-specific security rules.
- `general-security.yaml` — language-agnostic secret/key patterns.

Add a rule here (do not silently widen). To suppress a genuine false positive,
prefer a narrow `# nosemgrep: <rule-id>` annotation at the line with a reason,
not a blanket exclude.
