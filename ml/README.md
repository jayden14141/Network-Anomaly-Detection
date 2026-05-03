# ML Detection Pipeline

## Overview
Replacing static threshold-based detection with ML approaches.
Three phases, progressing from simple to complex.

## Phase 1: Tabular Anomaly Detection
- EWMA (Exponential Weighted Moving Average) — statistical baseline on packets/sec per source
- Isolation Forest — unsupervised anomaly detection
- XGBoost — supervised classification (upper-bound reference)
- Dataset: CIC-IDS2017
- Goal: establish baseline metrics (precision, recall, F1) and compare against the existing rule-based detectors

## Phase 2: Sequential / Probabilistic Models
- Markov Chain — learn normal traffic state transitions, flag low-probability sequences
- Connects to my dissertation work on probabilistic data structures
- Goal: capture temporal attack patterns (slow scans, distributed floods) that tabular models miss

## Phase 3: Deep Learning (Future Work)
- LSTM / Temporal Convolutional Autoencoder on flow-windowed sequences
- GNN on host-host communication graphs
- Goal: zero-day detection via learned traffic embeddings

## Evaluation
Each model compared against:
- Existing rule-based detectors (7 attack types)
- EWMA statistical baseline
- Metrics: precision, recall, F1-score, false positive rate, detection latency

## Environment
- Google Colab Pro (GPU)
- CICIDS 2017 dataset
- scikit-learn, XGBoost, pandas, matplotlib
