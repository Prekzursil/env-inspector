```markdown
# env-inspector Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and workflows used in the `env-inspector` Python repository. It covers coding conventions, file organization, commit message standards, and step-by-step guides for common maintenance and refactoring tasks. Whether you're contributing code, maintaining CI configurations, or cleaning up test artifacts, this guide will help you follow established practices for consistency and quality.

## Coding Conventions

### File Naming
- Use **snake_case** for all Python files and modules.
  - Example: `controller_actions.py`, `test_security_helpers.py`

### Import Style
- Use **relative imports** within packages.
  - Example:
    ```python
    from .utils import shared_helper
    ```

### Export Style
- Use **named exports**; avoid wildcard (`*`) exports.
  - Example:
    ```python
    def useful_function():
        pass

    __all__ = ["useful_function"]
    ```

### Commit Messages
- Follow **conventional commit** style.
- Prefixes include: `ci`, `fix`, `refactor`, `chore`
- Example:
  ```
  refactor: extract shared dialog button row helper
  ```

## Workflows

### Cleanup Test Artifacts and .gitignore
**Trigger:** When test artifacts or temporary files are accidentally staged or new artifact types need to be ignored.  
**Command:** `/cleanup-artifacts`

1. Identify and remove `.tmp/pytest-of-root/pytest-*` test artifact directories and files from the repository.
2. Update `.gitignore` to include new patterns for artifacts (e.g., `.venv/`, coverage outputs, `.tmp/`).
3. Commit with a message referencing cleanup or untracking artifacts.

**Example:**
```bash
rm -rf .tmp/pytest-of-root/pytest-*
echo ".tmp/" >> .gitignore
git add .gitignore
git commit -am "chore: cleanup test artifacts and update .gitignore"
```

---

### CI Config Move or Update
**Trigger:** When CI tools (e.g., GuardRails, Codecov) require config file path corrections or updates to ignore files.  
**Command:** `/ci-config-update`

1. Move or update CI config files (e.g., `.guardrails.yml` to `.guardrails/config.yml`, update `codecov.yml`).
2. Adjust config content to scope scanning or ignore non-source files.
3. Commit with a message referencing CI, config, or ignore.

**Example:**
```bash
mkdir -p .guardrails
mv .guardrails.yml .guardrails/config.yml
git add .guardrails/config.yml
git commit -m "ci: move GuardRails config to correct location"
```

---

### Deduplicate Helper Refactor
**Trigger:** When duplicate logic is found in multiple modules or scripts (e.g., dialog button rows, report writing, clipboard handlers).  
**Command:** `/deduplicate-helper`

1. Identify duplicated code patterns across files.
2. Extract shared logic into a helper function or utility module.
3. Update all call sites to use the new shared helper.
4. Add or update unit tests for the new helpers.
5. Commit with a message referencing refactor, deduplication, or helpers.

**Example:**
```python
# In utils.py
def shared_dialog_button_row(...):
    # implementation

# In controller_actions.py and dialogs.py
from .utils import shared_dialog_button_row
```
```bash
git add env_inspector_gui/utils.py env_inspector_gui/controller_actions.py env_inspector_gui/dialogs.py
git commit -m "refactor: deduplicate dialog button row logic into shared helper"
```

---

## Testing Patterns

- Test files follow the pattern: `*.test.*`
- The specific testing framework is **unknown**, but tests are likely Python unit tests.
- Place test files alongside the code they test or in a `tests/` directory.
- Example test file: `tests/test_security_helpers.py`

## Commands

| Command              | Purpose                                                      |
|----------------------|--------------------------------------------------------------|
| /cleanup-artifacts   | Remove test artifacts and update `.gitignore`                |
| /ci-config-update    | Move or update CI configuration files                        |
| /deduplicate-helper  | Refactor and deduplicate shared helper logic                 |
```