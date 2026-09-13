# SentinelAI

SentinelAI is a defensive AI-powered network intrusion detection and analysis platform for an academic cybersecurity project.

The project combines:

- 3 supervised algorithms: Logistic Regression, Random Forest, XGBoost
- 3 unsupervised algorithms: K-Means, DBSCAN, Isolation Forest
- 1 deep-learning model: 1D CNN
- FastAPI backend
- SQLite detection database
- HTML/CSS/JavaScript dashboard
- LLM-based AI Agent with model and database tools

## Current scope

SentinelAI currently analyzes **network-flow features** and classifies flows using the trained model. It does not automatically exploit targets or run offensive actions.

The runtime architecture is:

```text
Network-flow features
        |
        v
Preprocessing / StandardScaler
        |
        v
Best trained classifier
        |
        +--> prediction + confidence
        |
        v
SQLite detections
        |
        +--> FastAPI
        |
        +--> Dashboard
        |
        +--> AI Agent
```

## Important label limitation

The current processed dataset only has a trustworthy semantic mapping for:

```text
1 -> Benign
```

Classes `2` through `11` are currently stored as generic names such as `Attack_2`, `Attack_3`, etc.

Do **not** present those numeric classes as specific attack families until the original preprocessing mapping is recovered or the dataset is rebuilt while preserving the original textual CSE-CIC-IDS2018 labels.

## Repository structure

```text
SentinelAI/
├── agent/          # LLM agent and its tools
├── api/            # FastAPI backend
├── data/processed/ # feature metadata, scaler and processed arrays
├── database/       # SQLite schema and population utilities
├── frontend/       # browser dashboard
├── models/         # model metadata/results; large binaries are ignored by Git
├── notebooks/      # EDA, preprocessing, ML, CNN and tuning
└── requirements.txt
```

## Python

Python 3.12 is recommended.

Create and activate a virtual environment on Windows:

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Environment configuration

Copy `.env.example` to `.env` and set your provider values.

```env
LLM_API_KEY=your_key_here
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL=openai/gpt-oss-120b
```

Never commit `.env` or a real API key.

## Run the API

From the project root:

```powershell
python -m uvicorn api.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Run the frontend

In a second terminal:

```powershell
cd frontend
python -m http.server 5500 --bind 127.0.0.1
```

Open:

```text
http://127.0.0.1:5500/
```

## Populate demo detections

The database population script uses the existing test set and trained classifier.

By default it is now **idempotent** for the same demo run: re-running it will not silently duplicate the same batch.

```powershell
python database/populate_from_test_set.py
```

To intentionally replace the previous demo batch:

```powershell
python database/populate_from_test_set.py --replace
```

The generated timestamps are simulated because the processed arrays do not contain original capture timestamps. The database records this fact explicitly.

## Custom flow classification

For a custom flow, omitted features are initialized from the training scaler mean rather than raw zero. This is safer than treating every missing network-flow feature as a literal zero.

A prediction produced from a partial feature dictionary is still an approximation and the API returns a warning indicating how many features were imputed.

## Confidence vs. risk

`confidence` is the classifier's estimated probability for its selected class.

The existing `risk_score` is retained for dashboard compatibility, but it is explicitly marked as **confidence-based**. It is not a true cyber-risk/severity score because the current project does not yet have a validated per-attack severity mapping.

## Model evaluation work still required

Before final academic submission, the ML notebooks should be rerun with:

1. a clear Train / Validation / Test separation,
2. final test evaluation performed once after model selection,
3. unsupervised labels used only for post-hoc evaluation,
4. stratified cross-validation for rare classes,
5. verified semantic attack labels from a trustworthy source.

The current branch should not claim specific attack-family names until that mapping is recovered.

## Defensive-use statement

SentinelAI is intended for defensive analysis, authorized monitoring, and academic research.
