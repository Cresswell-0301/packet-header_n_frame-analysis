from __future__ import annotations

COMMON_DEFAULTS = {
    "data_dir": "cleaned_dataset",
    "pattern": "*.csv",
    "label_col": "Label",
    "chunksize": 200000,
    "max_rows": 1500000,
    "per_chunk_sample": 0.15,
    "random_state": 42,
    "rows_per_file": 80000,
}

MODEL_DEFAULTS = {
    "rf": {
        "model_out": "random_forest/rf_model.joblib",
        "meta_out": "random_forest/rf_model_meta.json",
        "n_estimators": 200,
        "max_depth": 20,
    },
    "svm": {
        "model_out": "support_vector_machine/svm_model.joblib",
        "meta_out": "support_vector_machine/svm_model_meta.json",
        "C": 1.0,
        "calib_method": "sigmoid",
    },
    "knn": {
        "model_out": "k_nearest_neighbors/knn_model.joblib",
        "meta_out": "k_nearest_neighbors/knn_model_meta.json",
        "k": 25,
        "weights": "distance",
        "metric": "minkowski",
        "p": 2,
    },
    "dt": {
        "model_out": "decision_tree/dt_model.joblib",
        "meta_out": "decision_tree/dt_model_meta.json",
        "max_depth": 20,
        "min_samples_split": 10,
        "min_samples_leaf": 10,
        "criterion": "gini",
    },
}
