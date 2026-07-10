# Contributing

Thanks for your interest in improving this toolkit.

## Ground rules

1. **No sensitive data, ever.** Do not commit tenant IDs, customer names, user
   principal names, audit output, screenshots of internal portals, or secrets.
   The `.gitignore` excludes common output formats (`*.csv`, `*.log`, `output/`),
   but the responsibility is yours — scrub before you commit.
2. **Least privilege.** Tools should request the minimum scopes/permissions
   needed and document them clearly.
3. **Test before you PR.** Validate against a demo or non-production tenant.

## How to contribute

1. Fork the repo and create a feature branch (`feature/my-tool`).
2. Follow the existing structure — organize by tool in a top-level folder
   (e.g., `sentinel-role-change-solution/`), each with its own README.
3. Include a `README.md` in any new tool folder covering: purpose, prerequisites,
   parameters, usage examples, and sanitized sample output.
4. Open a pull request with a clear description of what the tool does and how you
   tested it.

## Style

- PowerShell: use approved verbs (`Get-`, `Set-`, `New-`), comment-based help at
  the top of each script, and parameter validation.
- Prefer reusable helpers over copy-pasted connection logic.
