import os

DIR_ROOT = os.path.dirname(os.path.abspath(__file__))
DIR_RQ = os.path.join(DIR_ROOT, 'rq')
DIR_CSV_DATA = os.path.join(DIR_ROOT, 'data', 'csv')
DIR_JSON_DATA = os.path.join(DIR_ROOT, 'data', 'json')

JSON_DATA = {
    'security_updates': os.path.join(DIR_JSON_DATA, 'security_updates'),
    'security_updates_combined': os.path.join(DIR_JSON_DATA, 'security_updates_combined')
}
CSV_DATA = {
    'pr_vulnerabilities': os.path.join(DIR_CSV_DATA, 'pr_vulnerabilities.csv'),
    'dependabot_filtered_repos': os.path.join(DIR_CSV_DATA, 'dependabot_filtered_repos.csv'),
    'fixes_labels_round_2': os.path.join(DIR_CSV_DATA, 'fixes_labels_round_2.csv'),
    'stage_2_second_rater_true': os.path.join(DIR_CSV_DATA, 'stage_2_second_rater_true.csv'),
    'security_advisories_modified': os.path.join(DIR_CSV_DATA, 'security_advisories_modified.csv'),
    'fixes_commits_times': os.path.join(DIR_CSV_DATA, 'fixes_commits_times.csv'),
    'fixes_labels': os.path.join(DIR_CSV_DATA, 'fixes_labels.csv'),
    'security_updates_commits': os.path.join(DIR_CSV_DATA, 'security_updates_commits.csv'),
    'repo_popularity': os.path.join(DIR_CSV_DATA, 'repo_popularity.csv')
}
