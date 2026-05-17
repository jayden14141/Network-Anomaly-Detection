# Network Anomaly Detection: From Rule-Based algorithm to ML

A network traffic analysis and intrusion detection tool, paired with an ML study on the same problem.

> Originally developed as a team project in university.

## The Existing System (`code/`)

A live packet capture and analysis tool built on Scapy + PyQt5.

- **Live capture** of packets on a chosen interface, plus reading/writing of PCAP files.
- **Interactive GUI** with filtering, sorting, and traffic graphs (protocol frequency, IP/MAC network maps, source/destination address frequency).
- **Seven rule-based attack detectors:**
  1. TCP SYN flood
  2. ARP spoofing
  3. TCP port scanning
  4. Generic DoS
  5. ICMP flood
  6. HTTP flood
  7. DNS flood

Each detector triggers when a hand-tuned threshold (packets/sec, connection count, etc.) is crossed.

## ML Study (`ml/`)

A One-vs-Rest study on CIC-IDS2017: rather than one global attack/benign classifier, train a dedicated binary classifier per attack type (14 total) and compare four model families across them.

- **Models compared:** Random Forest, XGBoost, LightGBM, Autoencoder (reconstruction-error anomaly detector).
- **Attack grouping by sample size:** Large (≥10k), Medium (1k–10k), Small (<1k) — handled in separate notebooks so small-class caveats stay isolated.
- **Per-attack feature selection** via Random Forest importance (top-10 features per attack).
- **Evaluation:** 3-fold stratified CV + 80/20 holdout, reporting precision/recall/F1 and training time, aggregated into per-attack heatmaps and recall-vs-sample-size / speed-vs-recall plots.

See [`ml/README.md`](ml/README.md) for the full write-up.

## Repo Structure

```
code/      Rule-based detector + GUI (capstone deliverable, frozen)
ml/        ML study (notebooks + write-up)
data/      Datasets (gitignored)
docs/      User guide for the GUI
Research/  Background research from the capstone
```

`code/` and `ml/` are independent — `code/` runs standalone as the original tool; `ml/` is a self-contained Colab-based study.

## Setup (existing system)

```bash
pip install -r requirements.txt
python code/pythonGUI/main.py
```

For platform-specific notes (Windows / macOS Intel / macOS Arm64), see [`docs/Guide/setup.md`](docs/Guide/setup.md).
