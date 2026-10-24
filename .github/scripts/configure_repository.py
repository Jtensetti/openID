"""Apply the reviewed repository policy using the owner's existing GitHub CLI session.

No credential is accepted as an argument or printed. Existing branch protection is
never replaced automatically: a stricter rule must be reviewed before changing it.
"""
import argparse
import json
from pathlib import Path
import subprocess

REPO = 'Jtensetti/openID'
ROOT = Path(__file__).resolve().parents[2]


def api(path, *args):
    return subprocess.check_output(['gh', 'api', '-H', 'Accept: application/vnd.github+json',
        '-H', 'X-GitHub-Api-Version: 2026-03-10', path, *args], text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    policy = ROOT/'.github/branch-protection.json'
    if not args.apply:
        print(policy.read_text())
        print('Preview only. --apply requires an existing authorized gh session with repository administration rights.')
        return
    repo = json.loads(api('repos/'+REPO))
    if not repo.get('permissions', {}).get('admin'): raise SystemExit('Repository administration rights required.')
    branch = json.loads(api('repos/'+REPO+'/branches/main'))
    if branch['protected']: raise SystemExit('Existing branch protection must be reviewed; nothing was replaced.')
    api('repos/'+REPO+'/branches/main/protection', '--method', 'PUT', '--input', str(policy))
    protected = json.loads(api('repos/'+REPO+'/branches/main/protection'))
    checks = protected['required_status_checks']['checks']
    reviews = protected['required_pull_request_reviews']
    if (not protected['enforce_admins']['enabled'] or not protected['required_status_checks']['strict']
            or not any(c['context']=='assurance-gate' and c['app_id']==15368 for c in checks)
            or reviews['required_approving_review_count'] < 1 or not reviews['dismiss_stale_reviews']
            or not reviews['require_last_push_approval'] or not protected['required_conversation_resolution']['enabled']
            or protected['allow_force_pushes']['enabled'] or protected['allow_deletions']['enabled']):
        raise SystemExit('Protection response did not match the policy. Inspect the current settings.')
    api('repos/'+REPO+'/private-vulnerability-reporting', '--method', 'PUT')
    if not json.loads(api('repos/'+REPO+'/private-vulnerability-reporting'))['enabled']:
        raise SystemExit('Private reporting was not enabled. Branch protection was applied.')
    print('Verified: main protection, trusted assurance gate, independent approval and private vulnerability reporting.')


if __name__ == '__main__': main()
