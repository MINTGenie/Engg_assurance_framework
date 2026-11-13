---
description: Run an EAF Level 1 source assessment and summarise the result
---
Run `eaf assess ${input:path:.} --depth 1 --output eaf-reports` in the terminal (offline; do
not add `--allow-network` unless I say so). Then read `eaf-reports/eaf-report.json` and give me:

1. Overall status and reason, the git revision and whether the work tree was dirty.
2. A table of all checks with status FAIL or WARNING and their most severe findings (`file:line`, rule, message).
3. All checks that are NOT EXECUTED, with the reason, and any languages that were not assessed.
4. Suggested fixes for the FAIL findings, most severe first.

Do not call the result a certification, a compliance statement or an approval. Do not add
suppressions or change the policy or profile without asking me.
