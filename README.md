# Replication of "Investigating the Resolution of Vulnerable Dependencies with Dependabot Security Updates"

**Paper Title:** Investigating the Resolution of Vulnerable Dependencies with Dependabot Security Updates  
**Authors:** Mohayeji et al. (MSR 2023)  
**Replication Team:** Pragya Chapagain, Rabeya [Last Name]  
**Course:** CS-UH 3260 Software Analytics, NYUAD  

## Brief Description

The original paper studies how developers respond to Dependabot security update pull requests on GitHub, analyzing merge rates, manual fix behavior, and resolution timelines across 978 projects and 4,195 PRs collected up to May 31, 2020.

This replication reproduces RQ1 and RQ2 using the original scripts and data, and extends the study by selecting 10 repositories without Dependabot version updates enabled, mining new security update PRs through early 2026, and re-running the RQ1 analysis on the combined dataset.

---

## Repository Structure

```
README.md                          # This file
datasets/
  json/
    security_updates/              #original per-repo JSON files from the artifact (2019–2020)
  repo_popularity.csv              #repository popularity metrics (stars, forks) from original artifact
replication_scripts/
  pull_requests.py                 #modified: hardcoded 10 selected repos, updated output directory
  filter_pull_requests.py          #modified: date range June 1 2020 to present, updated I/O paths
  security_updates.py              #modified: hardcoded 10 repos, updated I/O paths; extracts Dependabot PRs
  combined_data.py                 #new: merges original 2019–2020 data with new 2020–2026 data
  RQ1_extension.ipynb              #extended RQ1 analysis notebook 
  const.py                         #path configuration for notebooks
outputs/
  pull_requests/                   #raw PR JSON files for the 10 repos (from pull_requests.py)
  pull_requests_filtered/          #filtered PRs from June 1 2020 onward (from filter_pull_requests.py)
  security_updates/                #dependabot-only PRs for the 10 repos (from security_updates.py)
  security_updates_combined/       #combined 2019–2026 Dependabot PRs per repo (from combined_data.py)
logs/                              #screenshots of console output from data collection runs
  consoleOutput1                   #outptut from running mining script
  consoleOutput2                   #outptut from running mining script
```

---

## Setup Instructions

### Prerequisites

- **OS:** macOS, Linux, or Windows
- **Python:** 3.9 or higher
- **Required packages:**

```bash
pip install pandas scipy statsmodels seaborn matplotlib jupyter
```

### Installation Steps

1. Clone this repository:
   ```bash
   git clone https://github.com/PC1-23/Replication-2--CS-UH-3260-Software-Analytics.git
   cd Replication-2--CS-UH-3260-Software-Analytics
   ```

2. Install dependencies:
   ```bash
   pip install pandas scipy statsmodels seaborn matplotlib jupyter
   ```

### Data Collection (Mining Post-2020 PRs)

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

### Running the RQ1 Extension Analysis

1. Update paths in `replication_scripts/const.py` if your directory layout differs.
2. Open and run the notebook:
   ```bash
   jupyter notebook replication_scripts/RQ1_extension.ipynb
   ```
   The notebook reads from `outputs/security_updates_combined/`, computes per-repo merge ratios and group assignments, runs Mann-Whitney U tests with Bonferroni correction, and computes Spearman correlations with repository popularity metrics.

---

## GenAI Usage

**Claude (Anthropic)** was used during this replication for the following:

- Troubleshooting LaTeX compilation errors in Overleaf

