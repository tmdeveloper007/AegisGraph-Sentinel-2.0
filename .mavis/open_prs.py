#!/usr/bin/env python3
"""Open 10 PRs for AegisGraph-Sentinel-2.0"""
import urllib.request, json, os, subprocess, time

GH_TOKEN = os.environ.get("GH_TOKEN", "")
HEADERS = {
    "Authorization": f"token {GH_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "Content-Type": "application/json"
}
UPSTREAM = "Puneet04-tech/AegisGraph-Sentinel-2.0"
FORK = "tmdeveloper007"
WORKSPACE = "/workspace/aegisgraph"

# 10 PRs: (issue_num, file_path, commit_msg, pr_title, pr_body)
PRS = [
    (2545, "src/threat_hunting/campaign_detector.py",
     "refactor : added return type annotation to CampaignDetector.__init__",
     "refactor : added return type annotation to CampaignDetector.__init__",
     "## Summary of What Has Been Done\n\nAdded `-> None` return type annotation to `CampaignDetector.__init__` in `src/threat_hunting/campaign_detector.py`.\n\n## Changes Made\n\n- Added `-> None` return type annotation to the constructor method.\n\n## Impact it Made\n\n- Consistent with type annotation standards across the codebase.\n- No runtime behavioral change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2545"),
    (2546, "src/case_workflow/workflow_engine.py",
     "docs : added docstring to get_dashboard method",
     "docs : added docstring to get_dashboard method",
     "## Summary of What Has Been Done\n\nAdded a docstring to `get_dashboard` in `src/case_workflow/workflow_engine.py`.\n\n## Changes Made\n\n- Added docstring to `get_dashboard` method with Returns section.\n\n## Impact it Made\n\n- Better documentation for the workflow dashboard endpoint.\n- No runtime change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2546"),
    (2547, "src/knowledge_os/knowledge_engine.py",
     "refactor : added return type annotation to KnowledgeEngine.__init__",
     "refactor : added return type annotation to KnowledgeEngine.__init__",
     "## Summary of What Has Been Done\n\nAdded `-> None` return type annotation to `KnowledgeEngine.__init__` in `src/knowledge_os/knowledge_engine.py`.\n\n## Changes Made\n\n- Added `-> None` return type annotation to constructor.\n\n## Impact it Made\n\n- Consistent type coverage in the knowledge OS module.\n- No behavioral change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2547"),
    (2548, "src/autonomous_investigation/decision_engine.py",
     "refactor : added return type annotation to DecisionIntelligenceEngine.__init__",
     "refactor : added return type annotation to DecisionIntelligenceEngine.__init__",
     "## Summary of What Has Been Done\n\nAdded `-> None` return type annotation to `DecisionIntelligenceEngine.__init__` in `src/autonomous_investigation/decision_engine.py`.\n\n## Changes Made\n\n- Added `-> None` return type annotation to constructor.\n\n## Impact it Made\n\n- Consistent type coverage in the autonomous investigation module.\n- No behavioral change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2548"),
    (2549, "src/exposure_management/service.py",
     "refactor : added return type annotation to ExposureService.__init__",
     "refactor : added return type annotation to ExposureService.__init__",
     "## Summary of What Has Been Done\n\nAdded `-> None` return type annotation to `ExposureService.__init__` in `src/exposure_management/service.py`.\n\n## Changes Made\n\n- Added `-> None` return type annotation to constructor.\n\n## Impact it Made\n\n- Consistent type coverage in the exposure management module.\n- No behavioral change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2549"),
    (2550, "src/reporting/service.py",
     "docs : added docstring to get_reporting_service function",
     "docs : added docstring to get_reporting_service function",
     "## Summary of What Has Been Done\n\nAdded a docstring to `get_reporting_service` in `src/reporting/service.py`.\n\n## Changes Made\n\n- Added docstring to `get_reporting_service` singleton getter function.\n\n## Impact it Made\n\n- Better documentation for the reporting service API.\n- No runtime change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2550"),
    (2551, "src/entity_resolution/entity_resolver.py",
     "refactor : added return type annotation to EntityResolver.__init__",
     "refactor : added return type annotation to EntityResolver.__init__",
     "## Summary of What Has Been Done\n\nAdded `-> None` return type annotation to `EntityResolver.__init__` in `src/entity_resolution/entity_resolver.py`.\n\n## Changes Made\n\n- Added `-> None` return type annotation to constructor.\n\n## Impact it Made\n\n- Consistent type coverage in the entity resolution module.\n- No behavioral change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2551"),
    (2552, "src/alert_correlation/correlation_engine.py",
     "docs : added docstring to get_dashboard in AlertCorrelationEngine",
     "docs : added docstring to get_dashboard in AlertCorrelationEngine",
     "## Summary of What Has Been Done\n\nAdded a docstring to `get_dashboard` in `src/alert_correlation/correlation_engine.py`.\n\n## Changes Made\n\n- Added docstring to `get_dashboard` method with Returns section.\n\n## Impact it Made\n\n- Better API documentation for the alert correlation dashboard.\n- No runtime change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2552"),
    (2553, "src/inference/explainer.py",
     "refactor : added return type annotation to AegisModelExplainer.__init__",
     "refactor : added return type annotation to AegisModelExplainer.__init__",
     "## Summary of What Has Been Done\n\nAdded `-> None` return type annotation to `AegisModelExplainer.__init__` in `src/inference/explainer.py`.\n\n## Changes Made\n\n- Added `-> None` return type annotation to constructor.\n\n## Impact it Made\n\n- Consistent type coverage in the inference module.\n- No behavioral change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2553"),
    (2554, "src/reporting/service.py",
     "refactor : added return type annotation to ReportingService.__init__",
     "refactor : added return type annotation to ReportingService.__init__",
     "## Summary of What Has Been Done\n\nAdded `-> None` return type annotation to `ReportingService.__init__` in `src/reporting/service.py`.\n\n## Changes Made\n\n- Added `-> None` return type annotation to constructor.\n\n## Impact it Made\n\n- Consistent type coverage in the reporting module.\n- No behavioral change.\n\n## Note: Please assign this PR to the `tmdeveloper007` account.\n\nCloses #2554"),
]

def run(cmd, cwd=WORKSPACE):
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0 and "everything up-to-date" not in result.stderr.lower():
        print(f"  CMD failed: {cmd[:60]}")
        print(f"  stderr: {result.stderr[:200]}")
    return result

# Get current upstream master SHA
result = run("git rev-parse upstream/master")
upstream_sha = result.stdout.strip()
print(f"Upstream master SHA: {upstream_sha}")

results = []

for i, (issue_num, changed_file, commit_msg, pr_title, pr_body) in enumerate(PRS):
    branch = f"#{issue_num}"
    print(f"\n--- PR {i+1}/10: Issue #{issue_num} -> {branch} ---")

    # Create branch from upstream master
    run(f"git checkout -b {branch} upstream/master")

    # Commit
    run(f"git add {changed_file}")
    commit_result = run(f"git commit -m '{commit_msg}'")
    if commit_result.returncode != 0:
        print(f"  Commit failed: {commit_result.stderr[:200]}")
        # Check if already committed
        if "nothing to commit" in commit_result.stderr:
            print("  Nothing to commit - file already has the change")
        else:
            results.append((issue_num, branch, "COMMIT_FAILED", commit_result.stderr[:200]))
            run("git checkout master")
            continue

    # Push to fork
    push_result = run(f"git push fork {branch} --force 2>&1")
    if push_result.returncode != 0:
        print(f"  Push failed: {push_result.stderr[:200]}")
        results.append((issue_num, branch, "PUSH_FAILED", push_result.stderr[:200]))
        run("git checkout master")
        continue

    # Create PR using GitHub API
    pr_body_final = pr_body.replace("{issue_num}", str(issue_num))
    pr_data = {
        "title": pr_title,
        "body": pr_body_final,
        "head": f"{FORK}:{branch}",
        "base": "master"
    }
    data = json.dumps(pr_data).encode()
    url = f"https://api.github.com/repos/{UPSTREAM}/pulls"
    req = urllib.request.Request(url, data=data, headers=HEADERS, method="POST")
    try:
        resp = urllib.request.urlopen(req)
        pr_result = json.loads(resp.read())
        pr_url = pr_result.get("html_url", "N/A")
        pr_num = pr_result.get("number", "N/A")
        print(f"  PR #{pr_num}: {pr_url}")
        results.append((issue_num, branch, pr_num, pr_url))
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"  PR creation failed: {e.code}: {err[:300]}")
        results.append((issue_num, branch, "PR_FAILED", err[:300]))

    # Back to master
    run("git checkout master")
    time.sleep(1)

print("\n\n=== FINAL RESULTS ===")
for issue_num, branch, status, detail in results:
    print(f"Issue #{issue_num} | Branch {branch} | {status} | {detail}")

with open("/workspace/aegisgraph/.mavis/pr_results.json", "w") as f:
    json.dump(results, f)
print("Saved results to .mavis/pr_results.json")
