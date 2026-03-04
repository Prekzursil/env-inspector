# Env-Inspector True-Zero Baseline (2026-03-04)

## Branch and Scope
- Branch: `fix/true-zero-provider-parity-r4`
- Base: `origin/main` (`f0a7362`)
- Worktree: `C:\Users\prekzursil\Desktop\workspace\worktrees\env-inspector-true-zero-r4`

## Required Branch-Protection Contexts
Command:
```bash
gh api repos/Prekzursil/env-inspector/branches/main/protection/required_status_checks --jq '.contexts'
```
Output:
```json
["Coverage 100 Gate","Codecov Analytics","Quality Zero Gate","SonarCloud Code Analysis","Codacy Static Code Analysis","DeepScan","Snyk Zero","Sentry Zero","Sonar Zero","Codacy Zero","DeepScan Zero"]
```

## Current Scanner/Provider State

### Code Scanning (GitHub)
Command:
```bash
gh api "repos/Prekzursil/env-inspector/code-scanning/alerts?state=open&ref=refs/heads/main&per_page=100" --jq 'length'
```
Output:
```text
0
```

### SonarCloud Open Issues (main)
Command:
```bash
python -c "import json,urllib.parse,urllib.request; q=urllib.parse.urlencode({'componentKeys':'Prekzursil_env-inspector','resolved':'false','ps':'1','branch':'main'}); u='https://sonarcloud.io/api/issues/search?'+q; d=json.load(urllib.request.urlopen(u)); print(d.get('paging',{}).get('total',-1))"
```
Output:
```text
29
```

### SonarCloud Open Hotspots (main)
Command:
```bash
python -c "import json,urllib.parse,urllib.request; q=urllib.parse.urlencode({'projectKey':'Prekzursil_env-inspector','status':'TO_REVIEW','ps':'1','branch':'main'}); u='https://sonarcloud.io/api/hotspots/search?'+q; d=json.load(urllib.request.urlopen(u)); print(d.get('paging',{}).get('total',-1))"
```
Output:
```text
1
```

### Codacy Current Issues (API total)
Command:
```bash
python -c "import json,urllib.request; u='https://api.codacy.com/api/v3/analysis/organizations/gh/Prekzursil/repositories/env-inspector/issues/search?limit=1'; data=json.dumps({'branchName':'main'}).encode(); req=urllib.request.Request(u,method='POST',headers={'accept':'application/json','content-type':'application/json'},data=data); d=json.load(urllib.request.urlopen(req)); print(d.get('pagination',{}).get('total',-1))"
```
Output:
```text
465
```

## Mismatch Evidence (Snyk Quota Override False-Green)
Command:
```bash
gh run list --repo Prekzursil/env-inspector --workflow "Snyk Zero" --branch main --limit 5
```
Latest run: `22681150361`

Command:
```bash
gh run view --repo Prekzursil/env-inspector 22681150361 --log | rg -n "quota|decision_reason"
```
Evidence excerpt:
```text
"oss_outcome": "quota_exhausted",
"code_outcome": "quota_exhausted",
"decision_reason": "quota_exhausted_override"
```

## Notes
- This baseline confirms required contexts can be green while provider dashboards still report open issues.
- Remediation branch converts zero-gate workflows to provider-count enforcement and changes Snyk policy to fail-closed for quota/inconclusive outcomes.
