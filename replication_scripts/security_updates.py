import sys
import requests
from tqdm import tqdm
import time
import pandas as pd
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
    def query_string(owner, name, number):
        return """
        query { 
          repository(owner:"%(owner)s", name:"%(name)s"){
            pullRequest(number:%(number)s) {
              timeline(last:100) {
                  edges {
                    node {
                      __typename
                      ... on ClosedEvent {
                        actor{
                          login
                          resourcePath
                        }
                      }
                    }
                  }
                }
              number
              createdAt
              title
              bodyText
              state
              closed
              merged
              closedAt
              mergedBy {
                login
                resourcePath
              }
              comments(first:100){
                nodes{
                  author {
                    login
                    resourcePath
                  }
                  bodyText
                  createdAt
                }
              }
              files(first:100) {
                nodes {
                  path
                }
              }
            }
          }
          rateLimit {
            remaining
            resetAt
          }
        }
        """ % {'owner': owner, 'name': name, 'number': number}

    def query_update(self, owner, name, number, level=0):
        def new_attempt(_time):
            time.sleep(_time)
            self.query_update(owner, name, number, level + 1)
            if level == 0:
                print('success!')

        try:
            request = requests.post(url='https://api.github.com/graphql',
                                    json={'query': self.query_string(owner, name, number)},
                                    headers={"Authorization": "Token " + manager.get_active_token()},
                                    timeout=10)
            if request.status_code == 200:
                self.response = request.json()
            else:
                print('query for (owner: {}, name {}, number: {}) failed: {}'.format(owner, name, number,
                                                                                     request.status_code))
                new_attempt(self.error_code_wait)
        except requests.exceptions.Timeout as err:
            print('query for (owner: {}, name {}, number: {}) failed: {}'.format(owner, name, number, err))
            new_attempt(self.timeout_wait)
        except requests.exceptions.ConnectionError as err:
            print('query for (owner: {}, name {}, number: {}) failed: {}'.format(owner, name, number, err))
            new_attempt(self.connection_loss_wait)

    def query_updates_all(self):
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
            pr_numbers = []
            try:
                with open(os.path.join(DIR_PRS_FILTERED, repo.replace('/', '@') + '_new.json'), 'r', encoding='utf-8') as json_file:
                    all_prs = json.load(json_file)
                    for pr in all_prs:
                        try:
                            if pr['author']['resourcePath'] == '/apps/dependabot':
                                pr_numbers.append(pr['number'])
                        except TypeError:
                            pass  # deleted user
            except IOError as err:
                print(err)
            prs = []
            slug = repo.split('/')
            owner = slug[0]
            name = slug[1]
            for pr_number in pr_numbers:
                self.query_update(owner, name, pr_number)
                try:
                    prs.extend([self.response['data']['repository']['pullRequest']])
                    rate_info = self.response['data']['rateLimit']
                    manager.update_state(rate_info)
                except TypeError as err:
                    print("failed (owner: {}, name: {}, number: {}): {}".format(owner, name, pr_number, err))
                    manager.decrease_remaining()
                    logs.append("failed (owner: {}, name: {}, number: {}): {}".format(owner, name, pr_number, err))
                except KeyError as err:
                    print("failed (owner: {}, name: {}, number: {}): {}".format(owner, name, pr_number, err))
                    manager.decrease_remaining()
                    logs.append("failed (owner: {}, name: {}, number: {}): {}".format(owner, name, pr_number, err))
            if prs:
                try:
                    with open(os.path.join(DIR_UPDATES, repo.replace('/', '@') + '_new.json'), 'w', encoding='utf-8') as output_file:
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
    requester.query_updates_all()
