# SentinelAI ML Methodology v2

This phase corrects the evaluation methodology without inventing semantic attack names.

## Data split
- 80% train
- 10% validation
- 10% final test
- stratified with random_state=42
- scaler fit on train only
- class weights computed from train only

## Model selection
Supervised models and the 1D CNN are compared on validation macro-F1.
The final test set is not loaded in notebooks 03 or 05.

## Hyperparameter tuning
XGBoost tuning uses:
- a rare-class-aware search subset,
- StratifiedKFold,
- macro-F1 scoring,
- sample_weight in RandomizedSearchCV.fit,
- sample_weight again for the full training fit.

The final test is evaluated only after the final model is selected by validation performance.

## Unsupervised learning
Labels are not used during unsupervised fitting:
- K-Means: the smaller cluster is treated as the anomaly cluster.
- Isolation Forest: contamination='auto'.
- DBSCAN: eps is selected from k-distance statistics; validation is approximated by nearest core samples.

Labels are used only after prediction for evaluation.

## Label mapping
The current numeric dataset does not contain a trustworthy semantic mapping for attack codes 2..11.
The notebooks therefore preserve Attack_2 ... Attack_11 until an original mapping is recovered.
If a future CSV contains textual labels, preprocessing preserves those textual names.
