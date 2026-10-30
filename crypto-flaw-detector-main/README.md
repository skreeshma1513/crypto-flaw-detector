# AI-Driven Crypto Flaw Detector - ML model + realtime scanner

Defensive static analysis only. Uploaded/dropped code is parsed with Python's `ast`, never executed.

## Run on Windows (VS Code terminal)
```
python --version
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python data\generate_training_data.py
python ai_model\train_model.py
python -m pytest
python realtime\watcher.py
```
PowerShell blocks activation? Run `Set-ExecutionPolicy -Scope Process Bypass` first.

## Realtime folder
1. Start `python realtime\watcher.py`
2. Copy any `.py` file (e.g. `data\sample_protocol.py`) into `realtime\watch\`
3. Findings print within ~2 seconds; results append to `realtime\results\realtime_log.jsonl`

## Pieces
- `data/training_data.csv` - 800 synthetic rows of Python crypto-API-misuse feature vectors (regenerate with `generate_training_data.py`)
- `ai_model/train_model.py` - RandomForest, saves `model.pkl` (auto-trained by `predict.py` if missing)
- `analyzer/` - AST rules CRY001-CRY012, feature extractor, explainable risk engine (0.7 static + 0.3 AI)

## Web app (dashboard)
```
python app.py
```
Open http://127.0.0.1:5000 -> **Scan Sample** -> results -> **Scan History** -> **View Report**.
Routes: `/`, `/upload`, `/analyze` (POST), `/results/<id>`, `/history`, `/report/<id>` (`?download=html|txt`), `/api/stats`.
The database (`database/scans.db`), uploads and reports folders are created automatically. Charts load Chart.js from a CDN (internet needed for charts only).
Tests: `python -m pytest`
