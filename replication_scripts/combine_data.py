import json
import os
import sys

sys.path.append('..')
from finder import *

repos = [
    'b2wads/grimorio-ui',
    'idena-network/idena-desktop',
    'rand256/valetudo',
    'vpython/glowscript',
    'grommet/grommet-designer',
    'omni/tokenbridge',
    'wordproof/wordproof-timestamp',
    'JuanIrache/gopro-telemetry',
    'linode/developers',
    'mobxjs/mst-gql'
]

DIR_COMBINED = os.path.join(os.path.dirname(DIR_ROOT), 'data', 'json', 'security_updates_combined')
os.makedirs(DIR_COMBINED, exist_ok=True)

for repo in repos:
    filename = repo.replace('/', '@') + '.json'
    new_filename = repo.replace('/', '@') + '_new.json'

    # special case for renamed repo
    if repo == 'omni/tokenbridge':
        original_path = os.path.join(os.path.dirname(DIR_ROOT), 'data', 'json', 'security_updates', 'poanetwork@tokenbridge.json')
    else:
        original_path = os.path.join(os.path.dirname(DIR_ROOT), 'data', 'json', 'security_updates', filename)
    
    new_path = os.path.join(DIR_UPDATES, new_filename)

    original_prs = []
    new_prs = []

    try:
        with open(original_path, 'r', encoding='utf-8') as f:
            original_prs = json.load(f)
        print(f"{repo}: loaded {len(original_prs)} original PRs")
    except IOError as e:
        print(f"{repo}: no original data found - {e}")

    try:
        with open(new_path, 'r', encoding='utf-8') as f:
            new_prs = json.load(f)
        print(f"{repo}: loaded {len(new_prs)} new PRs")
    except IOError as e:
        print(f"{repo}: no new data found - {e}")

    combined = original_prs + new_prs
    print(f"{repo}: combined total = {len(combined)} PRs")

    output_path = os.path.join(DIR_COMBINED, filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(combined, f, ensure_ascii=False, indent=4)

print("done")