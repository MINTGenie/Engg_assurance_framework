# Sample repositories for EAF validation

These directories are **test fixtures**. Three of them contain deliberately planted defects,
insecure patterns and **fake** credentials so that scanner adapters have something to find.
Do not copy code from here, and do not deploy it.

| Sample | Stack | Purpose |
|---|---|---|
| `vuln-python-service` | Python / Flask | injection, unsafe deserialisation, fake secrets, outdated pinned deps |
| `embedded-c-cpp` | C and C++ / CMake | buffer handling defects, null dereference, leak, uninitialised member |
| `web-ts-node` | JavaScript + TypeScript / Express | `eval`, loose equality, committed `.env`, outdated npm deps |
| `clean-python-lib` | Python library | negative control: should produce no findings |

The planted defects are listed in `docs/VALIDATION.md` together with what EAF actually reported.
