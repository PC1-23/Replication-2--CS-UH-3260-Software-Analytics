import sys
import json
import pandas as pd
from tqdm import tqdm
from datetime import datetime

sys.path.append('..')
from finder import *  # noqa: E402


def parse_time(time_string):
    return datetime.strptime(time_string, '%Y-%m-%dT%H:%M:%SZ')


if __name__ == '__main__':
    start_datetime = parse_time('2020-06-01T00:00:00Z')
    end_datetime = parse_time('2026-03-06T00:00:00Z')
    repo_names = [
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
    hasPRs = []
    for repo in tqdm(repo_names):
        try:
            with open(os.path.join(DIR_PRS, repo.replace('/', '@') + '_new.json'), 'r', encoding='utf-8') as json_file:
                prs = json.load(json_file)
                prs_filtered = []
                for pr in prs:
                    createdAt = parse_time(pr["createdAt"])
                    if (createdAt >= start_datetime) and (createdAt <= end_datetime):
                        prs_filtered.append(pr)
                if prs_filtered:
                    hasPRs.append(True)
                    try:
                        with open(os.path.join(DIR_PRS_FILTERED, repo.replace('/', '@') + '_new.json'), 'w', encoding='utf-8') as output_file:
                            json.dump(prs_filtered, output_file, ensure_ascii=False, indent=4)
                    except IOError as err:
                        print(err)
                else:
                    hasPRs.append(False)
        except IOError as err:
            hasPRs.append(False)