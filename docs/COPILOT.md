# Using EAF from GitHub Copilot

EAF does not need an LLM. The integration teaches Copilot how to run the CLI, how to work
spec-first on the practice findings, and how to talk about the result without overstating it.

| File | Used by | Purpose |
|---|---|---|
| `.github/copilot-instructions.md` | Copilot Chat / coding agent in this repository | repository conventions + EAF rules |
| `.github/skills/eaf-assess/SKILL.md` | Copilot agent skills | step-by-step procedure to run an assessment and report it |
| `.github/prompts/eaf-assess.prompt.md` | VS Code prompt files (`/eaf-assess`) | one-shot prompt |

To use the skill in another repository, copy `.github/skills/eaf-assess/` into that
repository's `.github/skills/` (or your personal skills directory) and make sure `eaf` is on
PATH in the environment where the agent runs commands.

Not verified in this prototype: the files follow the documented Copilot formats, but they were
not exercised against a live Copilot agent from this environment.
