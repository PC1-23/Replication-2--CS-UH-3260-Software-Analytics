"""
Replication of RQ1 and RQ2 from:
  Mohayeji et al., "Investigating the Resolution of Vulnerable Dependencies
  with Dependabot Security Updates," MSR 2023.

This script re-runs the analysis using the provided data and scripts,
then compares replicated results with those reported in the paper.
"""

import itertools
import json
import os
import sys
import warnings
from ast import literal_eval
from collections import Counter

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.lines import Line2D
import numpy as np
import pandas as pd
import seaborn as sns
from scipy import stats
from scipy.stats import mannwhitneyu, norm
import statsmodels.stats.multitest as smt
from statsmodels.stats.multitest import multipletests

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# ── paths ──
DIR_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIR_RQ = os.path.join(DIR_ROOT, 'rq')
DIR_CSV_DATA = os.path.join(DIR_ROOT, 'datasets_mily', 'csv')
DIR_JSON_DATA = os.path.join(DIR_ROOT, 'datasets_mily', 'json')

JSON_DATA = {
    'security_updates': os.path.join(DIR_JSON_DATA, 'security_updates')
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

SEP = "=" * 72


# ═══════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS (from the original notebooks)
# ═══════════════════════════════════════════════════════════════════════

def compute_bins2(arr, arr2, breaks, repo_names):
    densities = []
    bins = []
    for i in range(len(breaks)):
        temp = []
        for j, value in enumerate(arr):
            if i == 0:
                if value <= breaks[i]:
                    temp.append(arr2[j])
            else:
                if (value <= breaks[i]) & (value > breaks[i - 1]):
                    temp.append(arr2[j])
        if temp:
            densities.append(len(temp) / len(repo_names))
            bins.append(temp)
    return breaks, bins, densities


def fix_proportion2(fixes, mode='both'):
    absolute = [
        sum(fixes['by'] == 'human') + sum(fixes['by'] == 'bot'),
        len(fixes.index) - sum(fixes['by'] == 'human') - sum(fixes['by'] == 'bot'),
        sum(fixes['by'] == 'bot'),
        sum(fixes['by'] == 'human')
    ]
    relative = [
        round((sum(fixes['by'] == 'human') + sum(fixes['by'] == 'bot')) / len(fixes.index) * 100, 2),
        round((len(fixes.index) - sum(fixes['by'] == 'human') - sum(fixes['by'] == 'bot')) / len(fixes.index) * 100, 2),
        round(sum(fixes['by'] == 'bot') / (sum(fixes['by'] == 'human') + sum(fixes['by'] == 'bot')) * 100, 2),
        round(sum(fixes['by'] == 'human') / (sum(fixes['by'] == 'human') + sum(fixes['by'] == 'bot')) * 100, 2)
    ]
    if mode == 'both':
        return absolute, relative
    elif mode == 'absolute':
        return absolute
    elif mode == 'relative':
        return relative
    return None


def fix_proportion_constrained(fixes, prs, lower, upper, mode='both'):
    combo = fixes.merge(prs, how='inner', on='repository')
    return fix_proportion2(combo[(combo['prs'] > lower) & (combo['prs'] < upper)], mode)


# ═══════════════════════════════════════════════════════════════════════
#  RQ1 REPLICATION
# ═══════════════════════════════════════════════════════════════════════

def run_rq1():
    print(SEP)
    print("  RQ1: How often do developers merge Dependabot security updates?")
    print(SEP)

    # ── 1. Overall statistics ──
    pr_vuln = pd.read_csv(CSV_DATA['pr_vulnerabilities'], index_col=False)
    pr_vuln['severities'] = pr_vuln['severities'].apply(literal_eval)

    total_prs = len(pr_vuln)
    num_projects = len(pr_vuln.groupby('repository').count())
    open_prs = sum(pr_vuln['state'] == 'OPEN')
    closed_prs = sum(pr_vuln['state'] == 'CLOSED')
    merged_prs = sum(pr_vuln['state'] == 'MERGED')
    non_open = closed_prs + merged_prs
    merge_pct = merged_prs / non_open * 100

    print("\n── Overall PR Statistics ──")
    print(f"  Total PRs:        {total_prs}")
    print(f"  Projects:         {num_projects}")
    print(f"  Open:             {open_prs} ({open_prs / total_prs * 100:.2f}%)")
    print(f"  Closed:           {closed_prs} ({closed_prs / total_prs * 100:.2f}%)")
    print(f"  Merged:           {merged_prs}")
    print(f"  Non-open:         {non_open}")
    print(f"  Merge ratio:      {merge_pct:.2f}%")

    # ── 2. Per-project merge ratios ──
    repo_names = pd.read_csv(CSV_DATA['dependabot_filtered_repos'], index_col=False)['repository'].tolist()

    projects_with_closed = []
    merged_list = []
    total_list = []
    ratio_list = []
    for repo_name in repo_names:
        if repo_name not in pr_vuln.repository.unique().tolist():
            continue
        json_path = os.path.join(JSON_DATA['security_updates'], repo_name.replace('/', '@') + '.json')
        with open(json_path, 'r', encoding='utf-8') as f:
            prs = json.load(f)
            c, o, m = 0, 0, 0
            for pr in prs:
                if pr['state'] == 'CLOSED':
                    c += 1
                elif pr['state'] == 'OPEN':
                    o += 1
                elif pr['state'] == 'MERGED':
                    m += 1
            if c + m:
                projects_with_closed.append(repo_name)
                merged_list.append(m)
                total_list.append(m + c)
                ratio_list.append(m / (m + c))

    print(f"\n  Projects with non-open PRs: {len(projects_with_closed)}")

    # ── 3. Group classification (quantile-based) ──
    breaks, bins, densities = compute_bins2(total_list, ratio_list, [2, 4, 10, 67], repo_names)

    group_labels = ['Very low [1,2]', 'Low [3,4]', 'High [5,10]', 'Very high [11,67]']
    group_keys = ['[1,2]', '[3,4]', '[5,10]', '[11,67]']

    number_of_prs = []
    merge_rates = []
    for i, value in enumerate(breaks):
        if i == 0:
            for j in bins[i]:
                number_of_prs.append(group_keys[i])
                merge_rates.append(j)
        else:
            for j in bins[i]:
                number_of_prs.append(group_keys[i])
                merge_rates.append(j)

    df = pd.DataFrame({'group': number_of_prs, 'merge_ratio': merge_rates})

    print("\n── Table III: Distribution of Merge Ratios per Project Group ──")
    print(f"  {'Group':<20} {'Count':>6} {'Min':>6} {'25%':>6} {'Med':>6} {'75%':>6} {'Max':>6} {'Avg':>6} {'Std':>6}")
    print("  " + "-" * 68)

    paper_table3 = {
        '[1,2]':   {'min': 0, 'q25': 0, 'med': 50, 'q75': 100, 'max': 100, 'avg': 49, 'std': 47},
        '[3,4]':   {'min': 0, 'q25': 0, 'med': 75, 'q75': 100, 'max': 100, 'avg': 59, 'std': 43},
        '[5,10]':  {'min': 0, 'q25': 0, 'med': 80, 'q75': 100, 'max': 100, 'avg': 57, 'std': 42},
        '[11,67]': {'min': 0, 'q25': 26, 'med': 78, 'q75': 94, 'max': 100, 'avg': 61, 'std': 38},
    }

    for gk, gl in zip(group_keys, group_labels):
        grp = df[df['group'] == gk]['merge_ratio'] * 100
        desc = grp.describe()
        print(f"  {gl:<20} {int(desc['count']):>6} {desc['min']:>5.0f}% {desc['25%']:>5.0f}% {desc['50%']:>5.0f}% {desc['75%']:>5.0f}% {desc['max']:>5.0f}% {desc['mean']:>5.0f}% {desc['std']:>5.0f}%")

    all_ratios = df['merge_ratio'] * 100
    desc_all = all_ratios.describe()
    print(f"  {'Total':<20} {int(desc_all['count']):>6} {desc_all['min']:>5.0f}% {desc_all['25%']:>5.0f}% {desc_all['50%']:>5.0f}% {desc_all['75%']:>5.0f}% {desc_all['max']:>5.0f}% {desc_all['mean']:>5.0f}% {desc_all['std']:>5.0f}%")

    # ── 4. Mann-Whitney U tests with Bonferroni correction ──
    print("\n── Mann-Whitney U Tests (Bonferroni corrected) ──")
    categories = df['group'].unique()
    pvalues_list = []
    pairs = []
    for i in range(len(categories)):
        for j in range(i + 1, len(categories)):
            g1, g2 = categories[i], categories[j]
            stat, p = mannwhitneyu(
                df[df['group'] == g1]['merge_ratio'].values,
                df[df['group'] == g2]['merge_ratio'].values
            )
            pvalues_list.append(p)
            pairs.append((g1, g2))

    bonf = smt.multipletests(pvalues_list, alpha=0.05, method='bonferroni')
    for idx, (g1, g2) in enumerate(pairs):
        reject = "REJECT H0" if bonf[0][idx] else "Cannot reject H0"
        print(f"  {g1:>8} vs {g2:<8}  p={pvalues_list[idx]:.6f}  corrected_p={bonf[1][idx]:.4f}  {reject}")

    # ── 5. Spearman correlation ──
    repo_popularity = pd.read_csv(CSV_DATA['repo_popularity'])
    numeric_cols = repo_popularity.select_dtypes(include=[np.number])
    spearman = numeric_cols.corr(method="spearman")
    rho_stars = spearman['ratio']['stars']
    rho_forks = spearman['ratio']['forks']

    print(f"\n── Spearman Correlation (merge ratio vs popularity) ──")
    print(f"  Stars: ρ = {rho_stars:.6f}")
    print(f"  Forks: ρ = {rho_forks:.6f}")

    # ── Comparison with paper ──
    print(f"\n── RQ1 Comparison with Paper ──")
    print(f"  {'Metric':<40} {'Paper':>10} {'Replicated':>12} {'Match':>6}")
    print("  " + "-" * 70)

    comparisons = [
        ("Total PRs", "4416", str(total_prs)),
        ("Projects", "978", str(num_projects)),
        ("Non-open PRs", "4195", str(non_open)),
        ("Merged PRs", "2391", str(merged_prs)),
        ("Merge ratio (overall)", "57%", f"{merge_pct:.0f}%"),
        ("Spearman (stars)", "0.16", f"{rho_stars:.2f}"),
        ("Spearman (forks)", "0.16", f"{rho_forks:.2f}"),
        ("MW-U all pairs", "p≥0.15", f"p≥{min(bonf[1]):.2f}"),
    ]
    for metric, paper, repl in comparisons:
        match = "YES" if paper.replace("≥", "").strip() == repl.replace("≥", "").strip() or \
                         paper.strip("~") in repl else "CHECK"
        print(f"  {metric:<40} {paper:>10} {repl:>12} {match:>6}")

    return df


# ═══════════════════════════════════════════════════════════════════════
#  RQ2 REPLICATION
# ═══════════════════════════════════════════════════════════════════════

def run_rq2():
    print("\n\n" + SEP)
    print("  RQ2: How frequently do developers fix a vulnerable dependency")
    print("       manually in the presence of a Dependabot security update?")
    print(SEP)

    # ── Load data ──
    fixes = pd.read_csv(CSV_DATA['fixes_labels_round_2'], index_col=False)
    pr_vuln = pd.read_csv(CSV_DATA['pr_vulnerabilities'], index_col=False)
    pr_vuln = pr_vuln[pr_vuln['state'] != 'OPEN']

    projects = set(pr_vuln['repository'].to_list())
    pr_nums_list = []
    for project in projects:
        pr_nums_list.append(len(pr_vuln[pr_vuln['repository'] == project].index))
    pr_nums = pd.DataFrame({'repository': list(projects), 'prs': pr_nums_list})

    total_vulns = len(fixes)
    total_non_open_prs = len(pr_vuln)

    print(f"\n── Data Summary ──")
    print(f"  Non-open PRs:               {total_non_open_prs}")
    print(f"  Total vulnerabilities:       {total_vulns}")

    # ── Overall fix proportions ──
    bot_fixes = sum((fixes['by'] == 'bot') & (fixes['fixed'] == True))
    human_fixes = sum((fixes['by'] == 'human') & (fixes['fixed'] == True))
    not_fixed = total_vulns - bot_fixes - human_fixes
    total_fixed = bot_fixes + human_fixes

    bot_pct = bot_fixes / total_vulns * 100
    human_pct = human_fixes / total_vulns * 100
    not_fixed_pct = not_fixed / total_vulns * 100
    bot_share = bot_fixes / total_fixed * 100
    human_share = human_fixes / total_fixed * 100

    print(f"\n── Overall Vulnerability Fix Proportions ──")
    print(f"  Fixed by bot:      {bot_fixes} ({bot_pct:.2f}%)")
    print(f"  Fixed by human:    {human_fixes} ({human_pct:.2f}%)")
    print(f"  Not fixed:         {not_fixed} ({not_fixed_pct:.2f}%)")
    print(f"  Among fixes — Bot: {bot_share:.2f}%, Human: {human_share:.2f}%")
    print(f"  Bot fixes / human fixes ratio: {bot_fixes / human_fixes:.1f}x")

    # ── Per-project-group analysis (Table IV) ──
    prs_per_project = pr_vuln.groupby('repository')['number'].count().reset_index()

    def get_category(num):
        if 1 <= num <= 2:
            return '[1,2]'
        elif 3 <= num <= 4:
            return '[3,4]'
        elif 5 <= num <= 10:
            return '[5,10]'
        elif 11 <= num <= 67:
            return '[11,67]'
        return None

    prs_per_project['category'] = prs_per_project['number'].apply(get_category)

    if 'category' not in fixes.columns:
        fixes = pd.merge(
            fixes,
            prs_per_project[['repository', 'category']],
            on='repository',
            how='inner'
        )
        fixes['category'] = fixes['category'].astype(str)

    n_repos_after_merge = len(fixes['repository'].unique())
    n_vulns_after_merge = len(fixes)

    print(f"\n  Repos after merge with PR data: {n_repos_after_merge}")
    print(f"  Vulnerabilities after merge:    {n_vulns_after_merge}")

    # Fixed vs not-fixed per group
    resultsrq21 = fixes.groupby(by=['category', 'fixed'])['case'].count().reset_index()
    resultsrq21['total'] = 0
    for cat in resultsrq21.category.unique():
        tot = resultsrq21[resultsrq21['category'] == cat].case.sum()
        resultsrq21.loc[resultsrq21['category'] == cat, 'total'] = tot
    resultsrq21['perc'] = (resultsrq21['case'] / resultsrq21['total']) * 100
    pivot1 = pd.pivot_table(resultsrq21, values='perc', index=['category'], columns=['fixed'], aggfunc=np.sum)

    # Bot vs human per group
    resultsrq22 = fixes.groupby(by=['category', 'by'])['case'].count().reset_index()
    resultsrq22['total'] = 0
    for cat in resultsrq22.category.unique():
        tot = resultsrq22[resultsrq22['category'] == cat].case.sum()
        resultsrq22.loc[resultsrq22['category'] == cat, 'total'] = tot
    resultsrq22['perc'] = (resultsrq22['case'] / resultsrq22['total']) * 100
    pivot2 = pd.pivot_table(resultsrq22, values='perc', index=['category'], columns=['by'], aggfunc=np.sum)

    # Total row
    total_fixed_or_not = fixes.groupby(by=['fixed'])['case'].count().reset_index()
    total_fixed_or_not['perc'] = (total_fixed_or_not['case'] / total_fixed_or_not.case.sum()) * 100

    total_by = fixes[(fixes['by'] != '') & (fixes['fixed'] == True)].groupby(by=['by'])['case'].count().reset_index()
    total_by['perc'] = (total_by['case'] / total_by.case.sum()) * 100

    paper_table4 = {
        '[1,2]':   {'fixed': 76.35, 'not_fixed': 23.65, 'bot': 52.83, 'human': 47.17},
        '[3,4]':   {'fixed': 90.77, 'not_fixed':  9.23, 'bot': 61.36, 'human': 38.64},  # paper says 19.23 for low not_fixed — but that's the "not fixed" value. Wait, paper says Low fixed=90.77, not_fixed=9.23? Let me re-check
        '[5,10]':  {'fixed': 86.04, 'not_fixed': 13.96, 'bot': 64.11, 'human': 35.89},
        '[11,67]': {'fixed': 84.07, 'not_fixed': 15.93, 'bot': 71.11, 'human': 28.89},
    }

    print("\n── Table IV: Percentages per Project Group ──")
    print(f"  {'Group':<16} {'Fixed':>8} {'Not Fixed':>10} {'|':>2} {'Bot':>8} {'Human':>8}")
    print("  " + "-" * 56)

    group_order = ['[1,2]', '[3,4]', '[5,10]', '[11,67]']
    for gk in group_order:
        fixed_pct = pivot1.loc[gk, True] if True in pivot1.columns else 0
        not_fixed_pct = pivot1.loc[gk, False] if False in pivot1.columns else 0
        bot_pct_g = pivot2.loc[gk, 'bot'] if 'bot' in pivot2.columns else 0
        human_pct_g = pivot2.loc[gk, 'human'] if 'human' in pivot2.columns else 0
        print(f"  {gk:<16} {fixed_pct:>7.2f}% {not_fixed_pct:>9.2f}% {'|':>2} {bot_pct_g:>7.2f}% {human_pct_g:>7.2f}%")

    total_fixed_pct = total_fixed_or_not[total_fixed_or_not['fixed'] == True]['perc'].values[0]
    total_not_fixed_pct = total_fixed_or_not[total_fixed_or_not['fixed'] == False]['perc'].values[0]
    total_bot_pct = total_by[total_by['by'] == 'bot']['perc'].values[0]
    total_human_pct = total_by[total_by['by'] == 'human']['perc'].values[0]
    print(f"  {'Total':<16} {total_fixed_pct:>7.2f}% {total_not_fixed_pct:>9.2f}% {'|':>2} {total_bot_pct:>7.2f}% {total_human_pct:>7.2f}%")

    # ── Chi-squared test: Fixed vs Not Fixed ──
    print("\n── Chi-squared Test: Fixed vs Not Fixed ──")
    observed_1 = np.array([
        fix_proportion_constrained(fixes, pr_nums, 0, 3, mode='absolute')[0:2],
        fix_proportion_constrained(fixes, pr_nums, 2, 5, mode='absolute')[0:2],
        fix_proportion_constrained(fixes, pr_nums, 4, 11, mode='absolute')[0:2],
        fix_proportion_constrained(fixes, pr_nums, 10, 68, mode='absolute')[0:2]
    ])
    print(f"  Contingency table:\n{observed_1}")

    stat1, p1, dof1, expected1 = stats.chi2_contingency(observed_1)
    n1 = observed_1.sum()
    cramer_v1 = ((stat1 / n1) / 1) ** 0.5

    print(f"  χ² = {stat1:.4f}, p = {p1:.2e}, Cramer's V = {cramer_v1:.4f}")

    # Post-hoc pairwise (Benjamini-Hochberg)
    combinations = list(itertools.combinations(range(0, 4), 2))
    p_values_1 = []
    for i, j in combinations:
        _, p, _, _ = stats.chi2_contingency(observed_1[[i, j], :])
        p_values_1.append(p)

    bh_result_1 = multipletests(p_values_1, method='fdr_bh')
    p_adjusted_1 = bh_result_1[1]

    group_names = ['Very low', 'Low', 'High', 'Very high']
    print("\n  Post-hoc pairwise (BH corrected) — Fixed vs Not Fixed:")
    for idx, (i, j) in enumerate(combinations):
        sig = ""
        if p_adjusted_1[idx] < 0.001:
            sig = "***"
        elif p_adjusted_1[idx] < 0.01:
            sig = "**"
        elif p_adjusted_1[idx] < 0.05:
            sig = "*"
        print(f"    {group_names[i]:>10} vs {group_names[j]:<10}  p_adj = {p_adjusted_1[idx]:.2e} {sig}")

    # ── Chi-squared test: Bot vs Human ──
    print("\n── Chi-squared Test: Bot vs Human ──")
    observed_2 = np.array([
        fix_proportion_constrained(fixes, pr_nums, 0, 3, mode='absolute')[2:4],
        fix_proportion_constrained(fixes, pr_nums, 2, 5, mode='absolute')[2:4],
        fix_proportion_constrained(fixes, pr_nums, 4, 11, mode='absolute')[2:4],
        fix_proportion_constrained(fixes, pr_nums, 10, 68, mode='absolute')[2:4]
    ])
    print(f"  Contingency table:\n{observed_2}")

    stat2, p2, dof2, expected2 = stats.chi2_contingency(observed_2)
    n2 = observed_2.sum()
    cramer_v2 = ((stat2 / n2) / 1) ** 0.5

    print(f"  χ² = {stat2:.4f}, p = {p2:.2e}, Cramer's V = {cramer_v2:.4f}")

    # Post-hoc pairwise (Benjamini-Hochberg)
    p_values_2 = []
    for i, j in combinations:
        _, p, _, _ = stats.chi2_contingency(observed_2[[j, i], :])
        p_values_2.append(p)

    bh_result_2 = multipletests(p_values_2, method='fdr_bh')
    p_adjusted_2 = bh_result_2[1]

    print("\n  Post-hoc pairwise (BH corrected) — Bot vs Human:")
    for idx, (i, j) in enumerate(combinations):
        sig = ""
        if p_adjusted_2[idx] < 0.001:
            sig = "***"
        elif p_adjusted_2[idx] < 0.01:
            sig = "**"
        elif p_adjusted_2[idx] < 0.05:
            sig = "*"
        print(f"    {group_names[i]:>10} vs {group_names[j]:<10}  p_adj = {p_adjusted_2[idx]:.2e} {sig}")

    # ── Comparison with paper ──
    print(f"\n── RQ2 Comparison with Paper ──")
    print(f"  {'Metric':<45} {'Paper':>10} {'Replicated':>12} {'Match':>6}")
    print("  " + "-" * 75)

    comparisons = [
        ("Total vulnerabilities", "4978", str(total_vulns)),
        ("Non-open PRs", "4195", str(total_non_open_prs)),
        ("Fixed by bot", "2662 (53.48%)", f"{bot_fixes} ({bot_pct:.2f}%)"),
        ("Fixed by human", "1507 (30.27%)", f"{human_fixes} ({human_pct:.2f}%)"),
        ("Not fixed", "809 (16.25%)", f"{not_fixed} ({not_fixed_pct:.2f}%)"),
        ("Bot share of fixes", "63.85%", f"{bot_share:.2f}%"),
        ("Human share of fixes", "36.15%", f"{human_share:.2f}%"),
        ("χ² (fixed vs not) p-value", "1.19e-15", f"{p1:.2e}"),
        ("Cramer's V (fixed vs not)", "0.12", f"{cramer_v1:.2f}"),
        ("χ² (bot vs human) p-value", "9.89e-14", f"{p2:.2e}"),
        ("Cramer's V (bot vs human)", "0.12", f"{cramer_v2:.2f}"),
    ]

    for metric, paper, repl in comparisons:
        print(f"  {metric:<45} {paper:>10} {repl:>12}")

    # Per-group comparison
    print(f"\n  Per-group comparison with Table IV:")
    print(f"  {'Group':<10} {'Metric':<15} {'Paper':>8} {'Replicated':>12} {'Match':>6}")
    print("  " + "-" * 55)
    for gk in group_order:
        fixed_pct = pivot1.loc[gk, True]
        not_fixed_pct_g = pivot1.loc[gk, False]
        bot_pct_g = pivot2.loc[gk, 'bot']
        human_pct_g = pivot2.loc[gk, 'human']
        p = paper_table4[gk]
        print(f"  {gk:<10} {'Fixed':<15} {p['fixed']:>7.2f}% {fixed_pct:>11.2f}% {'YES' if abs(p['fixed']-fixed_pct)<0.5 else 'DIFF':>6}")
        print(f"  {'':<10} {'Not fixed':<15} {p['not_fixed']:>7.2f}% {not_fixed_pct_g:>11.2f}% {'YES' if abs(p['not_fixed']-not_fixed_pct_g)<0.5 else 'DIFF':>6}")
        print(f"  {'':<10} {'Bot':<15} {p['bot']:>7.2f}% {bot_pct_g:>11.2f}% {'YES' if abs(p['bot']-bot_pct_g)<0.5 else 'DIFF':>6}")
        print(f"  {'':<10} {'Human':<15} {p['human']:>7.2f}% {human_pct_g:>11.2f}% {'YES' if abs(p['human']-human_pct_g)<0.5 else 'DIFF':>6}")

    return fixes


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("\n" + SEP)
    print("  REPLICATION STUDY — Mohayeji et al. (MSR 2023)")
    print("  RQ1 & RQ2 Analysis")
    print(SEP + "\n")

    run_rq1()
    run_rq2()

    print("\n\n" + SEP)
    print("  REPLICATION COMPLETE")
    print(SEP)
