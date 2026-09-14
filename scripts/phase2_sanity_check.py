from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
N = ROOT / "notebooks"

def source(path):
    nb = json.loads(path.read_text(encoding="utf-8"))
    return "\n".join("".join(c.get("source", [])) for c in nb["cells"])

checks = []

s01 = source(N / "01_eda_cleaning.ipynb")
checks.append(("EDA no broken .str benign on numeric label", 'df["Label"].str.lower().eq("benign")' not in s01))

s02 = source(N / "02_preprocessing.ipynb")
checks.append(("Train/validation/test split", "X_val.npy" in s02 and "test_size=0.50" in s02))
checks.append(("Scaler fit on train", "scaler.fit_transform(X_train_raw)" in s02))

s03 = source(N / "03_supervised.ipynb")
checks.append(("Supervised does not load X_test", 'X_test.npy' not in s03))
checks.append(("Supervised evaluates validation", 'X_val.npy' in s03))

s04 = source(N / "04_unsupervised.ipynb")
checks.append(("Isolation Forest does not use attack ratio", "contamination=float(attack_ratio)" not in s04))
checks.append(("Isolation Forest auto contamination", 'contamination="auto"' in s04))
checks.append(("KMeans does not map clusters from labels", "cluster_attack_ratio" not in s04))

s05 = source(N / "05_cnn.ipynb")
checks.append(("CNN does not load X_test", 'X_test.npy' not in s05))
checks.append(("CNN uses validation data", "validation_data=(X_val_cnn, y_val_enc)" in s05))

s06 = source(N / "06_tuning.ipynb")
checks.append(("Tuning uses StratifiedKFold", "StratifiedKFold" in s06))
checks.append(("Search passes sample_weight", "sample_weight=sample_weight_search" in s06))
checks.append(("Final test explicitly after selection", "FINAL TEST" in s06))

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(("PASS" if ok else "FAIL"), "-", name)

if failed:
    raise SystemExit("Phase 2 sanity check failed: " + ", ".join(failed))

print("\nAll Phase 2 source-level methodology checks passed.")
