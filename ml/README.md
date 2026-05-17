# ML Detection Pipeline

A One-vs-Rest (OvR) study on CIC-IDS2017: train a dedicated binary classifier for each of the 14 attack types and compare four model families across them.

All work lives in Colab notebooks under `ml/notebooks/`. Intermediate artifacts (`cicids2017_cleaned.csv`, `attack_groups.json`, `attack_features.json`, per-group `results_*.json`) are written to Google Drive.

## Pipeline

| Notebook | Purpose |
|---|---|
| `01_data_exploration.ipynb` | Load CIC-IDS2017, strip column whitespace, drop infinite/NaN rows, fix Web Attack label encoding. Group attacks by sample size: **Large** (≥10k), **Medium** (1k–10k), **Small** (<1k). Save cleaned CSV + `attack_groups.json`. |
| `02_feature_selection.ipynb` | For each attack, train a Random Forest (attack vs. a 50k BENIGN sample) and keep the top-10 features by importance. Save `attack_features.json` and a per-attack importance heatmap. |
| `03_ovr_large.ipynb` | OvR for large attacks. |
| `04_ovr_medium.ipynb` | OvR for medium attacks. |
| `05_ovr_small.ipynb` | OvR for small attacks, with stratify/CV relaxed when class counts are too low. |
| `06_evaluation.ipynb` | Aggregate the three per-group result files into a master table; plot recall and F1 heatmaps, recall vs. sample size, and speed vs. recall. |

## OvR Setup

For each attack:
- Use that attack's top-10 features (from notebook 02).
- Build a balanced dataset: all attack samples (capped at 50k) plus a random BENIGN sample at **5:1 BENIGN:attack** ratio.
- 80/20 stratified train/test split, plus 3-fold stratified CV on the training set.

## Models

| Model | Notes |
|---|---|
| Random Forest | 200 trees, max_depth=15, `class_weight='balanced'`. |
| XGBoost | 200 trees, max_depth=8, `scale_pos_weight = neg/pos`. |
| LightGBM | 200 trees, max_depth=8, `class_weight='balanced'`. |
| Autoencoder | Keras MLP autoencoder (dim → dim/2 → dim/4 → dim/2 → dim) trained on BENIGN only; flag samples whose reconstruction error exceeds the 95th percentile of BENIGN errors. |

Each model is scored on precision, recall, F1, and wall-clock training time.

## Evaluation (notebook 06)

- Master table: every (attack × model) combination with CV recall (mean±std), test precision/recall/F1, and time.
- Recall and F1 heatmaps across all 14 attacks × 4 models, with group dividers.
- Scatter plots: recall vs. attack training samples (log x); training time vs. recall (log x).
- Best-model-per-attack summary and a small-attack caveat (F1 on test sets with <10 attack samples is statistically noisy).

## Environment

- Google Colab Pro (GPU available, used for the autoencoder)
- CIC-IDS2017
- scikit-learn, XGBoost, LightGBM, TensorFlow/Keras, pandas, matplotlib, seaborn
