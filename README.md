# PhishGraph

**Machine Learning-Based Phishing Website Detection Using Graph ML and Fuzzy Logic**

An academic research prototype and portfolio project featuring a Flask cybersecurity dashboard, 15 deterministic URL features, graph-based semi-supervised label spreading, explainable Sugeno fuzzy inference, interactive topology exploration, asynchronous model training studio, and local SQLite audit history.

---

## Quick Start on Windows

Tested on Python 3.11 and 3.12. Open this folder in VS Code or PowerShell and run:

```powershell
# 1. Create and configure virtual environment
python -m venv --system-site-packages .venv

# 2. Install dependencies (if not already installed)
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 3. Generate synthetic data and train the initial demo model
.\.venv\Scripts\python.exe train.py --demo

# 4. Launch the application
.\.venv\Scripts\python.exe app.py
```

Open **http://127.0.0.1:5000** in your browser. Press `Ctrl+C` to stop.

Alternatively, execute `./start.ps1` in PowerShell.

*Linux/macOS users:* Replace `.\.venv\Scripts\python.exe` with `.venv/bin/python`.

---

## 10 Core Implemented Features

### 1. Batch URL Analysis & CSV Triage
- Paste dozens of URLs simultaneously or drag-and-drop a labeled/unlabeled CSV file.
- Automatic deduplication, syntax validation, and per-row error logging.
- Real-time risk distribution metrics (High, Review Needed, Low risk breakdown).
- Search, filter by risk verdict, and sort across batch results.
- Export results to **sanitized CSV** (protected against formula injection) and **executive PDF reports**.
- Sensible batch upload limits (capped at 200 items per request).

### 2. Interactive Graph Explorer
- Responsive vector visualization replacing static diagrams.
- Interactive radial topology showing the active query node connected to its $k=6$ nearest training nodes via RBF similarity weights:
  $$W_{ij} = \exp(-\gamma \|x_i - x_j\|^2)$$
- Controls for interactive zoom, pan, and reset.
- Node inspection panel: click or hover on any node to view hostname, Euclidean distance, RBF affinity, semi-supervised seed status (phishing seed, benign seed, or unlabeled node), and propagated probability.
- Clearly distinguishes between the displayed 6-nearest neighborhood and the underlying $N \times N$ dense adjacency matrix.

### 3. Detailed Explainability Panel
- Tri-evidence breakdown: Graph ML score, Lexical warning risk, and combined Sugeno fuzzy risk index.
- Comprehensive breakdown of all **15 lexical features** with plain-English descriptions and security rationales (e.g., Shannon entropy, userinfo delimiter, punycode prefixes, directory depth).
- Observed warning signals list displaying the exact heuristic weight contribution ($+0.10$ to $+0.30$).
- Active Sugeno rules listing showing antecedent activations ($\mu_A \times \mu_B$) and consequent outputs ($z_k$).
- Epistemic uncertainty and **limited-support indicators** when a candidate URL lies far outside the training distribution ($d_{\min} > 5.0$).

### 4. Fuzzy Logic Playground
- Real-time simulation interface to experiment with Graph ML and Lexical risk scores without affecting the active model.
- Dynamic canvas visualizer plotting continuous triangle membership functions for Low ($\max(0, 1 - 2x)$), Medium ($\max(0, 1 - |2x - 1|)$), and High ($\max(0, 2x - 1)$) fuzzy sets with input marker lines.
- $3 \times 3$ Sugeno Rule Matrix with live highlights indicating active rules and their product AND activations.
- Transparent formula breakdown computing the crisp weighted average:
  $$\text{Risk} = \frac{\sum w_i z_i}{\sum w_i}$$
- Quick scenario preset buttons: Zero-Day / Clean URL, Keyword Lure on New Host, Flagrant Phishing, and Benign Domain.

### 5. Model Comparison Dashboard
- Direct evaluation benchmarking across three architectures:
  1. **Logistic Regression Baseline** (trained on visible labels only)
  2. **Graph ML (LabelSpreading RBF)** (semi-supervised, propagates across labeled and unlabeled nodes)
  3. **Graph ML + Sugeno Fuzzy Logic** (combined multi-criteria inference)
- Complete evaluation metrics: Accuracy, Precision, Recall, F1-Score, and ROC-AUC computed on held-out test hosts.
- $2 \times 2$ Confusion Matrices displaying True Positives, False Positives, True Negatives, and False Negatives.
- Transparent provenance display: sample counts, host-disjoint holdout explanation, decision threshold ($0.50$), and prominent synthetic data badges.

### 6. Dataset Management & Validation
- Upload custom labeled CSV files (`url,label` format: $0 = \text{benign}, 1 = \text{phishing}$).
- Server-side validation: URL syntax verification, binary label validation, duplicate normalization, and conflict detection (identical URLs with opposing labels).
- Detailed validation summary report: class balance ($N_0, N_1$, ratio), unique host counts, and cross-class domain overlap warnings.
- Dataset registry recording version tags, upload timestamps, file sizes, and SHA-256 checksums.
- Strict security safeguard: URLs are validated strictly as text strings; no outbound HTTP, DNS, or socket calls are initiated.

### 7. Training & Experiment Studio
- Asynchronous non-blocking background training worker: the Flask web server remains 100% responsive during model training.
- Real-time job tracking (`idle`, `running`, `completed`, `failed`) with live log streaming.
- Hyperparameter tuning: RBF Gamma ($\gamma$), Alpha clamping factor ($\alpha$), Semi-supervised unlabel ratio, and random seeds.
- Model Experiment Registry: preserves past trained models in `artifacts/experiments/` with full metrics history.
- 1-click model activation: activate any completed experiment to immediately serve predictions without restarting the server.
- Fault tolerance: failed jobs record error tracebacks without corrupting the active model.

### 8. Searchable Analysis History & Privacy Safeguards
- Persistent SQLite database with automatic schema migrations.
- Audit explorer: search by hostname, filter by risk verdict (Low, Review, High), filter by scan type (single or batch), and sort columns.
- Server-side pagination with responsive controls.
- Inspection drawer showing complete evidence snapshots and feature values for past scans.
- **Privacy by Design**: Sensitive credentials (`user:pass@`), URL queries, and deep path tokens are stripped before storing records in SQLite.
- One-click deletion controls and clean empty states.

### 9. Professional Downloadable Reports
- High-quality, vector-rendered **downloadable PDF reports** for both single URL scans and batch analyses.
- Built using a pure-Python zero-dependency PDF 1.4 vector generator (no third-party binaries or network downloads required).
- Includes research header, composite risk index, verdict badge, tri-evidence breakdown, signals table, and nearest graph neighbors.
- Standalone print-ready HTML view (`/report/single/<id>`) formatted with `@media print` for browser printing and paper export.
- **Security safeguard**: Suspicious URLs are rendered as unlinked plain text in exported reports to prevent accidental clicks.

### 10. Guided Demonstration Mode & Viva Preparation
- Curated threat scenarios for live academic demonstrations:
  1. *Legitimate E-commerce Catalog* (Low risk)
  2. *Ambiguous Query on Unencrypted HTTP* (Review needed)
  3. *Subdomain Brand Impersonation Kit* (High risk)
  4. *Credential / Userinfo Delimiter Attack* (High risk)
- Step-by-step walkthrough of the 3-stage decision pipeline (Lexical Features $\to$ Graph ML $\to$ Sugeno Fuzzy Logic).
- Security misconceptions debunked: explains why HTTPS does NOT mean safe and why low risk is not a guarantee of safety.
- Comprehensive Academic Viva Glossary with definitions for Label Spreading, RBF kernels, Host-Disjoint splits, and Uncalibrated Scores.

---

## 10 Advanced Research Features (Next-Level Upgrades)

### 11. Adversarial Evasion & Mutation Robustness Engine
- Simulates realistic threat actor URL evasion vectors across 6 distinct mutation strategies:
  1. **Subdomain Padding**: Deep nesting with benign prefix tokens.
  2. **Hyphenation Bombing**: Mimicking trusted compound brand slugs.
  3. **Homoglyph & Leet Substitution**: Replacing Latin glyphs with numerical or Cyrillic lookalikes.
  4. **Userinfo Delimiter Cloaking**: Prepending fake credential authority blocks (`https://login@phish.net`).
  5. **Deep Path Padding**: Forcing high path segment depth to dilute host entropy.
  6. **TLD Swap**: Re-homing onto untrusted suspicious top-level domains.
- Computes empirical robustness delta $\Delta = \text{Risk}_{\text{perturbed}} - \text{Risk}_{\text{original}}$ and evasion flags.

### 12. Brand Impersonation & Typosquatting Radar
- Analyzes domain labels against a curated target matrix of top global brands (PayPal, Microsoft, Google, Apple, Amazon, Netflix, Meta, etc.).
- Evaluates Jaro-Winkler similarity ($S_{\text{jw}} \ge 0.85$) and Levenshtein edit distance ($d \le 2$).
- Performs phonetic and leet-speak normalization (`0 -> o`, `1 -> l`, `@ -> a`, `3 -> e`).

### 13. IDN Homograph & Punycode Confusable Detector
- RFC 3492 Punycode decoder (`xn--`) extracting true Unicode codepoints.
- Cross-script spoofing matrix detecting mixed Latin/Cyrillic/Greek alphabets (e.g. Cyrillic `а` (U+0430) vs. Latin `a` (U+0061)).
- Flags deceptive internationalized domain names designed to deceive human eyes.

### 14. Spectral Graph Topology & Homophily Analytics
- Computes global and local spectral graph invariants on the RBF similarity manifold:
  - **Graph Homophily Index** ($h$): Measures label cohesion across adjacent nodes ($h \in [0, 1]$).
  - **Clustering Coefficient**: Quantifies transitivity and triangle density in graph neighborhoods.
  - **Laplacian Spectral Trace** ($\mathrm{Tr}(\tilde{L})$): Evaluates graph smoothness under normalized Laplacian operator.
  - **Personalized PageRank (PPR)**: Quantifies query node centrality and stationary diffusion.

### 15. Adaptive / Tunable Sugeno Fuzzy Rule Studio
- Allows real-time tuning and saving of the 9-rule zero-order Sugeno consequent matrix.
- Preset profiles:
  - **Balanced (Default)**: Symmetrical standard calibrated risk profile.
  - **Aggressive (Zero-Trust)**: Amplified consequent outputs for high-security environments.
  - **Conservative**: Lower false-positive sensitivity for high-throughput enterprise gateways.

### 16. Multi-Domain Campaign Clustering
- Unsupervised Agglomerative RBF connected-component clustering across batch or historical URLs.
- Discovers co-occurring phishing campaigns sharing structural DNA and kit templates without needing prior labels.
- Computes campaign risk index, shared feature signatures, and domain membership lists.

### 17. OASIS STIX 2.1 Threat Intelligence Exporter
- Exports analysis records as standardized OASIS STIX 2.1 Cyber Threat Intelligence (CTI) JSON bundles.
- Generates STIX Domain Objects (SDOs): `Indicator`, `Observed-Data`, and `Infrastructure`.
- Fully mapped to **MITRE ATT&CK** kill-chain tactics: Initial Access (`T1566.002` Spearphishing Link) and Resource Development (`T1583.001` Domains).

### 18. Mandiant OpenIOC 1.1 XML Exporter
- Exports validated indicators in standardized OpenIOC XML schema.
- Readily ingestible into endpoint detection and response (EDR) platforms, enterprise SIEMs, and perimeter firewalls.

### 19. SOC Alert Triage Queue & Multi-Vendor Firewall Generator
- Operational Security Operations Center (SOC) triage workflow (`New`, `Investigating`, `Contained`, `False Positive`).
- Automatically generates copy-ready blocking rules for:
  - **Suricata / Snort IDS/IPS**: `alert http $HOME_NET any -> $EXTERNAL_NET any (...)`
  - **Linux iptables**: `iptables -A FORWARD -m string --string "..." -j DROP`
  - **Cisco ASA / IOS ACL**: `access-list PHISH_BLOCK deny tcp any host ...`
  - **DNS Sinkhole (RPZ)**: BIND 9 Response Policy Zone redirect.

### 20. Interactive Academic Viva Presentation Deck (`/presentation`)
- Built-in 8-slide presentation deck tailored for college project review and viva defense.
- Covers: Title & Motivation, Architecture Pipeline, 15 Deterministic Features, Spectral Graph ML, Sugeno Fuzzy Logic, Experimental Comparison Benchmarks, Advanced Cyber Defense Upgrades, and Project Summary.
- Includes interactive navigation (Next, Prev, Keyboard Arrows), print stylesheet, LaTeX equations, and examiner defense notes.

*(Bonus Integration)*: **Developer Webhook & API Studio** with HMAC-SHA256 signature verification preview.

---

## Project Structure

```text
PhishGraph_Mini_Project/
├── app.py                      # Flask API, routing, and application controller
├── train.py                    # Host-disjoint training, holdout split, and metrics
├── generate_demo.py            # Reproducible synthetic dataset generator
├── start.ps1                   # One-click Windows PowerShell launcher
├── requirements.txt            # Python dependencies (Flask, scikit-learn, numpy, scipy, joblib)
├── phishguard/
│   ├── features.py             # 15 deterministic URL features and lexical heuristics
│   ├── fuzzy.py                # Sugeno fuzzy inference, membership curves, and rule tuner
│   ├── model.py                # Detector class (LabelSpreading, Logistic baseline, batch predict)
│   ├── database.py             # SQLite persistence, migrations, search, and SOC triage
│   ├── datasets.py             # Dataset schema validation, checksums, and metadata
│   ├── trainer.py              # Background training worker, experiment runner, and registry
│   ├── reports.py              # Pure-Python vector PDF generator and sanitized CSV exporter
│   ├── adversarial.py          # 6 mutation vectors and attack robustness engine
│   ├── brand.py                # Jaro-Winkler, Levenshtein, and leet brand radar
│   ├── homograph.py            # Punycode decoder and cross-script confusable detector
│   ├── graph_analytics.py      # Spectral topology, homophily, and Laplacian metrics
│   ├── clustering.py           # Multi-domain campaign kit clustering
│   ├── stix.py                 # OASIS STIX 2.1 JSON and OpenIOC XML generators
│   └── soc.py                  # SOC triage pack and multi-vendor firewall ACL generator
├── templates/
│   ├── index.html              # Modern SaaS cybersecurity research dashboard
│   ├── report.html             # Print-ready presentation report template
│   └── presentation.html       # 8-slide interactive academic viva defense deck
├── static/
│   ├── style.css               # Navy/slate/teal theme, dark/light mode, responsive layout
│   └── app.js                  # Frontend client architecture, SVG graph, and feature controllers
├── tests/
│   ├── test_project.py         # 10 core regression test suites
│   └── test_new_features.py    # 10 advanced research feature test suites
├── artifacts/
│   ├── detector.joblib         # Active trained model artifact
│   ├── metrics.json            # Active model evaluation benchmark report
│   └── experiments/            # Experiment registry storing versioned models
├── data/
│   ├── demo.csv                # Demonstration dataset on reserved .test domains
│   └── datasets/               # Uploaded validated custom CSV datasets
└── instance/
    └── history.sqlite3         # Anonymized local scan audit history
```

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web dashboard |
| `GET` | `/presentation` | Interactive 8-slide Academic Viva presentation deck |
| `GET` | `/report/single/<id>` | Print-ready HTML analysis report |
| `GET` | `/api/health` | Model status, active version, and demo flag |
| `GET` | `/api/metrics` | Active model evaluation benchmarks and confusion matrices |
| `POST` | `/api/predict` | Single URL analysis (JSON: `{"url": "..."}`) |
| `POST` | `/api/predict/batch` | Batch triage (JSON: `{"urls": ["..."], "max_batch": 200}`) |
| `POST` | `/api/adversarial/simulate`| Evasion attack mutation simulator |
| `POST` | `/api/brand/analyze` | Brand impersonation and typosquatting radar |
| `POST` | `/api/homograph/analyze` | Punycode decoder and confusable character analyzer |
| `GET` | `/api/graph/spectral` | Spectral graph metrics (homophily, Laplacian trace) |
| `POST` | `/api/campaigns/cluster` | Multi-domain campaign kit clustering |
| `POST` | `/api/export/stix` | OASIS STIX 2.1 CTI bundle JSON exporter |
| `POST` | `/api/export/openioc` | Mandiant OpenIOC 1.1 XML exporter |
| `GET` | `/api/soc/triage` | SOC alert triage queue |
| `POST` | `/api/soc/triage` | Update triage record status and notes |
| `GET` | `/api/soc/pack/<id>` | Comprehensive incident remediation pack and ACLs |
| `POST` | `/api/fuzzy/profile` | Set active Sugeno profile (`balanced`, `aggressive`, `conservative`) |
| `POST` | `/api/api-console/simulate-webhook` | Dispatch simulated HMAC-SHA256 signed SIEM webhook |
| `POST` | `/api/export/batch/csv` | Export batch results as sanitized CSV |
| `POST` | `/api/export/batch/pdf` | Export batch executive summary PDF |
| `GET` | `/api/export/single/pdf/<id>`| Export single scan evaluation PDF |
| `POST` | `/api/export/current/pdf` | Export currently displayed analysis as PDF |
| `GET` | `/api/fuzzy/playground` | Fuzzy membership curve data and rule matrix |
| `GET` | `/api/fuzzy/simulate` | Live fuzzy simulation (`?graph=0.8&lexical=0.5`) |
| `GET` | `/api/datasets` | List registered datasets and metadata |
| `POST` | `/api/datasets/upload` | Upload and validate labeled CSV dataset |
| `GET` | `/api/training/status` | Current training job status and live logs |
| `POST` | `/api/training/start` | Launch background training job |
| `GET` | `/api/experiments` | List experiment history and model versions |
| `POST` | `/api/experiments/activate`| Activate a specific experiment model version |
| `GET` | `/api/history` | Paginated and filtered scan history (`?q=&verdict=&page=`) |
| `GET` | `/api/history/<id>` | Details of a specific historical scan |
| `DELETE` | `/api/history` | Clear all scan history (requires JSON payload) |
| `DELETE` | `/api/history/<id>` | Delete single scan record |
| `GET` | `/api/demo/samples` | Curated threat exemplars and viva glossary |

---

## Validation & Testing

Run the automated test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

All 11 unit test suites verify:
- URL parsing edge cases (IPv4/IPv6, internationalized punycode, `@` delimiters, ports).
- Monotonicity and full coverage of the 9 Sugeno fuzzy inference rules.
- Host-disjoint training/holdout split isolation.
- Conflicting dataset labels rejection.
- Single and batch prediction pipelines.
- Formula injection sanitization and CSV exports.
- Pure-Python PDF generation with standard headers and trailers.
- Real-time fuzzy playground mathematical correctness.
- Background training runner and model experiment activation.
- Privacy preservation (verifying userinfo, passwords, and deep paths are never stored).

---

## Scope and Ethical Limitations

1. **Passive Lexical Scope**: PhishGraph operates strictly as a static lexical analysis prototype. It never connects to evaluated URLs, performs DNS queries, or downloads HTML/DOM content.
2. **Uncalibrated Risk Index**: The composite risk score (0–100) represents a synthesized fuzzy inference index, not a calibrated statistical probability.
3. **Synthetic Demo Data**: The default 480 URLs are synthetically generated on reserved `.test` domains for demonstration purposes. Real-world deployments require curated, permitted external threat feeds.
4. **Host Isolation vs. Registrable Domains**: The 25% holdout isolates exact hostnames; sibling subdomains or shared infrastructure (e.g. cloud hosting) may still share patterns.
