# Network Anomaly Detection: From Rule-Based algorithm to ML

A network traffic analysis and intrusion detection tool, extended with a machine-learning detection pipeline.

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

## Planned ML Approach (`ml/`)

A phased pipeline, simple to complex:

1. **Tabular anomaly detection** — EWMA baseline, Isolation Forest, XGBoost (supervised upper bound).
2. **Sequential / probabilistic models** — Markov chains over traffic-state transitions, to catch temporal patterns the tabular models miss.
3. **Deep learning (future)** — LSTM / temporal-conv autoencoders, GNN over host-host graphs.

Trained and evaluated on **CIC-IDS2017**. Each model is benchmarked against the seven rule-based detectors on precision, recall, F1, false-positive rate, and detection latency.

See [`ml/README.md`](ml/README.md) for the full plan.

## Repo Structure

```
code/      Rule-based detector + GUI (capstone deliverable, frozen)
ml/        ML detection pipeline (notebooks, src, models, results)
data/      Datasets (gitignored)
docs/      User guide for the GUI
Research/  Background research from the capstone
```

`code/` and `ml/` are independent modules — `code/` runs standalone as the original tool, `ml/` runs standalone for training and evaluation. They are designed to connect later: trained models in `ml/models/` can score flows extracted by `code/`'s capture pipeline, replacing or augmenting the threshold-based detectors.

## Setup (existing system)

```bash
pip install -r requirements.txt
python code/pythonGUI/main.py
```

For platform-specific notes (Windows / macOS Intel / macOS Arm64), see [`docs/Guide/setup.md`](docs/Guide/setup.md).
