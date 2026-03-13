import sys
import requests
from tqdm import tqdm
import time
import pandas as pd
import numpy as np
import json

sys.path.append('..')
from finder import *  # noqa: E402
# from config import *  # noqa: E402
from token_management import TokenManagerGraphQL # noqa: E402


class RepositoryRequest:

    def __init__(self, error_code_wait=1, timeout_wait=2, connection_loss_wait=60):
        self.error_code_wait = error_code_wait
        self.timeout_wait = timeout_wait
        self.connection_loss_wait = connection_loss_wait
        self.response = None

    @staticmethod
    def query_string(owner, name, cursor):
        return """
        query { 
          repository(owner:"%(owner)s", name:"%(name)s") {
            pullRequests(first: 100, after: %(cursor)s) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                resourcePath
                checksResourcePath
                number
                author {
                  login
                  resourcePath
                  url
                }
                authorAssociation
                title
                bodyText
                labels(first:100){
                  nodes {
                    name
                    description
                  }
                }
                createdAt
                closed
                state
                closedAt
                publishedAt
                mergeable
                mergedBy {
                  login
                  resourcePath
                  url
                }
              }
            }
          }
          rateLimit {
            remaining
            resetAt
          }
        }
        """ % {'owner': owner, 'name': name, 'cursor': cursor}

    def query_prs_per_repo(self, owner, name, cursor, level=0):
        def new_attempt(_time):
            time.sleep(_time)
            self.query_prs_per_repo(owner, name, cursor, level + 1)
            if level == 0:
                print('success!')

        try:
            request = requests.post(url='https://api.github.com/graphql',
                                    json={'query': self.query_string(owner, name, cursor)},
                                    headers={"Authorization": "Token " + manager.get_active_token()},
                                    timeout=10)
            if request.status_code == 200:
                self.response = request.json()
            else:
                print('query for (owner: {}, name {}, cursor: {}) failed: {}'.format(owner, name, cursor,
                                                                                     request.status_code))
                new_attempt(self.error_code_wait)
        except requests.exceptions.Timeout as err:
            print('query for (owner: {}, name {}, cursor: {}) failed: {}'.format(owner, name, cursor, err))
            new_attempt(self.timeout_wait)
        except requests.exceptions.ConnectionError as err:
            print('query for (owner: {}, name {}, cursor: {}) failed: {}'.format(owner, name, cursor, err))
            new_attempt(self.connection_loss_wait)

    def query_prs_all(self):
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
        logs = []
        for repo in tqdm(repo_names):
            prs = []
            slug = repo.split('/')
            owner = slug[0]
            name = slug[1]
            has_next_page = True
            start_cursor = 'null'
            while has_next_page:
                self.query_prs_per_repo(owner, name, start_cursor)
                try:
                    page_info = self.response['data']['repository']['pullRequests']['pageInfo']
                    has_next_page = page_info['hasNextPage']
                    if has_next_page:
                        start_cursor = '"' + page_info['endCursor'] + '"'
                    prs.extend(self.response['data']['repository']['pullRequests']['nodes'])
                    rate_info = self.response['data']['rateLimit']
                    manager.update_state(rate_info)
                except TypeError as err:
                    print("failed (owner: {}, name: {}, cursor: {}): {}".format(owner, name, start_cursor, err))
                    has_next_page = False
                    manager.decrease_remaining()
                    logs.append("failed (owner: {}, name: {}, cursor: {}): {}".format(owner, name, start_cursor, err))
                except KeyError as err:
                    print("failed (owner: {}, name: {}, cursor: {}): {}".format(owner, name, start_cursor, err))
                    has_next_page = False
                    manager.decrease_remaining()
                    logs.append("failed (owner: {}, name: {}, cursor: {}): {}".format(owner, name, start_cursor, err))
            if prs:
                try:
                    with open(os.path.join(DIR_PRS, repo.replace('/', '@') + '_new.json'), 'w', encoding='utf-8') as output_file:
                        json.dump(prs, output_file, ensure_ascii=False, indent=4)
                except IOError as err:
                    print(err)
        try:
            with open(PATH_LOGS_DATA(os.path.basename(__file__)), 'w') as logs_file:
                for log in logs:
                    logs_file.write("%s\n" % log)
        except IOError as err:
            print(err)


if __name__ == '__main__':
    manager = TokenManagerGraphQL(GITHUB_TOKENS)
    requester = RepositoryRequest()
    requester.query_prs_all()
