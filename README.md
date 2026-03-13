# Replication of "Investigating the Resolution of Vulnerable Dependencies with Dependabot Security Updates"

**Paper Title:** Investigating the Resolution of Vulnerable Dependencies with Dependabot Security Updates  
**Authors:** H. Mohayeji, A. Agaronian, E. Constantinou, N. Zannone, and A. Serebrenik  
**Published in:** 2023 IEEE/ACM 20th International Conference on Mining Software Repositories (MSR), Melbourne, Australia, 2023, pp. 234-246  
**DOI:** [10.1109/MSR59073.2023.00042](https://doi.org/10.1109/MSR59073.2023.00042)  
**Original Artifact:** https://github.com/piwvh/dependabot-msr2023  
**Replication Team:** Rabeya Zahan Mily, Pragya Chapagain  
**Course:** CS-UH 3260 Software Analytics, NYUAD

## Brief Description

The original paper studies how developers respond to Dependabot security update pull requests on GitHub, analyzing merge rates, manual fix behavior, and resolution timelines across 978 projects and 4,195 PRs collected up to May 31, 2020.

This replication reproduces RQ1 and RQ2 using the original scripts and data, and extends the study by selecting 10 repositories without Dependabot version updates enabled, mining new security update PRs through early 2026, and re-running the RQ1 analysis on the combined dataset.

---

## Repository Structure

```
README.md                              # This file (top-level project documentation)
.gitignore                             # Git ignore rules

replication_scripts/
  replication_rq1_rq2.py               # Mily's replication script — re-runs RQ1 + RQ2 analysis
logs/
  replication_output.txt               # Console output from running replication_rq1_rq2.py

datasets_mily/                         # Datasets used for RQ1 + RQ2 reproduction (Mily)
  csv/
    pr_vulnerabilities.csv             # 4,416 Dependabot security update PRs (RQ1 + RQ2)
    dependabot_filtered_repos.csv      # 978 filtered JavaScript repositories (RQ1)
    repo_popularity.csv                # Stars, forks, watchers per repository (RQ1)
    fixes_labels_round_2.csv           # 4,978 vulnerability fix labels — bot/human/not fixed (RQ2)
    stage_2_second_rater_true.csv      # 213 manually labeled developer motivations (RQ2)
  json/
    security_updates/                  # 1,102 JSON files, one per repo (RQ1)

Replication-2--CS-UH-3260-Software-Analytics/   # Pragya's extension work (RQ1 post-2020)
  datasets/
    json/security_updates/             # Original per-repo JSON files from the artifact (2019–2020)
    repo_popularity.csv                # Repository popularity metrics (stars, forks)
  replication_scripts/
    pull_requests.py                   # Modified: hardcoded 10 repos, updated output directory
    filter_pull_requests.py            # Modified: date range June 1 2020 to present, updated I/O paths
    security_updates.py                # Modified: hardcoded 10 repos, updated I/O paths
    combine_data.py                    # New: merges original 2019–2020 data with new 2020–2026 data
    RQ1_extension.ipynb                # Extended RQ1 analysis notebook
    const.py                           # Path configuration for notebooks
  outputs/
    pull_requests/                     # Raw PR JSON files for the 10 repos
    pull_requests_filtered/            # Filtered PRs from June 1 2020 onward
    security_updates/                  # Dependabot-only PRs for the 10 repos
    security_updates_combined/         # Combined 2019–2026 Dependabot PRs per repo
  logs/
    consoleOutput1.png                 # Screenshot of mining script output
    consoleOutput2.png                 # Screenshot of mining script output
```

### Notes on Datasets

- **`datasets_mily/`** contains a subset of the original artifact — only the 5 CSV files and 1,102 JSON files needed for RQ1 and RQ2 reproduction.
- **`Replication-2/datasets/`** contains the same 1,102 JSON files and `repo_popularity.csv` (identical copies), used by Pragya's extension scripts.
- Both datasets originate from the same [artifact repo](https://github.com/piwvh/dependabot-msr2023). The data was pre-collected by the original authors via GitHub API.

---

## Setup Instructions

### Part 1: RQ1 + RQ2 Reproduction (Mily)

#### Prerequisites

| Requirement | Version Used | Notes |
|---|---|---|
| **OS** | macOS (darwin 25.2.0) | Should work on any OS with Python 3.8+ |
| **Python** | 3.12.6 | Any Python 3.8+ should work |
| **pandas** | 2.3.2 | Core data manipulation |
| **numpy** | latest | Numerical computation |
| **scipy** | latest | Statistical tests (Mann-Whitney U, chi-squared, Spearman) |
| **statsmodels** | latest | Multiple testing correction (Bonferroni, Benjamini-Hochberg) |

**R is NOT required.** The original `RQ2-RQ3.ipynb` calls an R script (`adjust_p.R`) for Benjamini-Hochberg correction. Our replication script replaces this with Python's `statsmodels.stats.multitest.multipletests(method='fdr_bh')`, which implements the identical procedure.

#### Installation Steps

1. **Clone this repository:**

```bash
git clone https://github.com/rabeyamily/mily-pragya-SoftwareAnalytics-ReplicationStudy02.git
cd mily-pragya-SoftwareAnalytics-ReplicationStudy02
```

2. **Create and activate a virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows
```

3. **Install Python dependencies:**

```bash
pip install pandas numpy scipy statsmodels
```

4. **Verify installation:**

```bash
python3 -c "import pandas; import numpy; import scipy; import statsmodels; print('All packages OK')"
```

5. **Run the replication:**

```bash
python3 replication_scripts/replication_rq1_rq2.py
```

This prints all RQ1 and RQ2 results to the console, including side-by-side comparisons with the paper's reported values.

To save the output to a file:

```bash
python3 replication_scripts/replication_rq1_rq2.py | tee logs/replication_output.txt
```

#### Notes on the Replication Script

The original authors' notebooks (`RQ1.ipynb`, `RQ2-RQ3.ipynb`) are available at the [original artifact repo](https://github.com/piwvh/dependabot-msr2023/tree/master/rq). Our `replication_rq1_rq2.py` extracts their analysis logic into a single standalone script, with the following fixes for modern Python:
- `seaborn.distplot` (deprecated in seaborn >= 0.12) is not used
- `DataFrame.append()` (removed in pandas >= 2.0) is not used
- The R script (`adjust_p.R`) for Benjamini-Hochberg correction is replaced with Python's `multipletests(method='fdr_bh')`
- `repo_popularity.corr()` is called only on numeric columns to avoid pandas 2.x errors

---

### Part 2: RQ1 Extension — Post-2020 Data (Pragya)

#### Prerequisites

- **OS:** macOS, Linux, or Windows
- **Python:** 3.9 or higher
- **Required packages:**

```bash
pip install pandas scipy statsmodels seaborn matplotlib jupyter
```

#### Data Collection (Mining Post-2020 PRs)

Run the scripts in the following order to reproduce the data collection pipeline.

> **Note:** A GitHub personal access token is required. Set it as an environment variable before running:
> ```bash
> export GITHUB_TOKEN=your_token_here
> ```


**1. `replication_scripts/pull_requests.py`**  
Mines all pull requests for the 10 selected repositories.  
- Hardcoded the list of 10 selected repos  
- Updated output directory to `outputs/pull_requests/` to avoid overwriting original data  
- Generates one JSON file per repo containing all PRs

```bash
python replication_scripts/pull_requests.py
```

**2. `replication_scripts/filter_pull_requests.py`**  
Filters PRs to the post-cutoff window (June 1, 2020 to present).  
- Hardcoded the list of 10 selected repos  
- Set start date to June 1, 2020 and end date to today  
- Reads from `outputs/pull_requests/` and writes to `outputs/pull_requests_filtered/`

```bash
python replication_scripts/filter_pull_requests.py
```

**3. `replication_scripts/security_updates.py`**  
Extracts Dependabot security update PRs from the filtered data.  
- Hardcoded the list of 10 selected repos  
- Updated input and output file paths  
- Writes results to `outputs/security_updates/`

```bash
python replication_scripts/security_updates.py
```

**4. `replication_scripts/combined_data.py`**  
Combines original (2019–2020) and new (2020–2026) Dependabot PR data per repo.  
- Loads original data from `datasets/json/security_updates/`  
- Loads new data from `outputs/security_updates/`  
- Concatenates and saves combined files to `outputs/security_updates_combined/`

```bash
python replication_scripts/combined_data.py
```

#### Running the RQ1 Extension Analysis

1. Update paths in `replication_scripts/const.py` if your directory layout differs.
2. Open and run the notebook:
   ```bash
   jupyter notebook replication_scripts/RQ1_extension.ipynb
   ```
   The notebook reads from `outputs/security_updates_combined/`, computes per-repo merge ratios and group assignments, runs Mann-Whitney U tests with Bonferroni correction, and computes Spearman correlations with repository popularity metrics.

---

## Replication Results Summary

### RQ1 + RQ2 Reproduction (Mily)

Both RQ1 and RQ2 are **fully replicated**. All key findings match the paper:

| Research Question | Status | Key Finding |
|---|---|---|
| **RQ1** | Fully Replicated | 57% of non-open security updates are merged. No significant differences between project groups (adjusted p >= 0.15). Weak correlation with popularity (rho = 0.16). |
| **RQ2** | Fully Replicated | 53.48% fixed by bot, 30.27% fixed manually, 16.25% not fixed. Bot fixes are 1.8x more frequent. Delegation to bot increases with number of security updates (p = 9.89e-14). |

The only discrepancy is a 0.14 percentage point difference in the Very high group of Table IV (paper: 84.07% fixed, replicated: 83.93%), which is already present in the original notebook's own output and is caused by a data merge step that drops 16 repositories.

---

## GenAI Usage

| Team Member | Tool | Usage |
|---|---|---|
| **Mily** | Cursor (Claude) | Explored artifact structure, debugged pandas 2.x compatibility issues |
| **Pragya** | Claude (Anthropic) | Troubleshooting LaTeX compilation errors in Overleaf |
