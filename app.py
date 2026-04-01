from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, List

import pandas as pd
from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent / 'packet-header_n_frame-analysis'
FYP_SCRIPT = PROJECT_ROOT / 'fyp1.py'
DATA_DIR = PROJECT_ROOT
MODEL_PATH = DATA_DIR / 'random_forest' / 'rf_model.joblib'

app = Flask(__name__, template_folder='templates', static_folder='static')


def _safe_name(value: str, default: str) -> str:
    value = (value or '').strip()
    if not value:
        return default
    name = os.path.basename(value)
    return name or default


def _run_command(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=str(DATA_DIR),
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace'
    )


def _load_fyp1_module() -> Any:
    if not FYP_SCRIPT.exists():
        raise FileNotFoundError(f'fyp1.py not found at {FYP_SCRIPT}')

    spec = importlib.util.spec_from_file_location('fyp1_dashboard_bridge', FYP_SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError('Unable to load fyp1.py')

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/review-logs')
def review_logs():
    scores_path = DATA_DIR / 'scores.csv'
    features_path = DATA_DIR / 'features.csv'
    capture_log_path = DATA_DIR / 'capture_live.txt'

    summary = {
        'total_rows': 0,
        'labels': {},
        'risk_levels': {},
        'score_avg': None,
        'top_records': [],
        'feature_rows': 0,
        'log_preview': ''
    }

    if scores_path.exists():
        try:
            df = pd.read_csv(scores_path)
            summary['total_rows'] = int(len(df))

            if 'label' in df.columns:
                summary['labels'] = {str(k): int(v) for k, v in df['label'].fillna('unknown').value_counts().to_dict().items()}

            if 'risk_level' in df.columns:
                summary['risk_levels'] = {str(k): int(v) for k, v in df['risk_level'].fillna('unknown').value_counts().to_dict().items()}

            if 'ip_fraud_score' in df.columns:
                score_series = pd.to_numeric(df['ip_fraud_score'], errors='coerce').dropna()

                if not score_series.empty:
                    summary['score_avg'] = round(float(score_series.mean()), 2)

            columns = [c for c in ['frame_no', 'ip_src', 'ip_dst', 'label', 'ip_fraud_score_display', 'risk_level'] if c in df.columns]

            if columns:
                ranked = df.copy()

                if 'ip_fraud_score' in ranked.columns:
                    ranked['ip_fraud_score_num'] = pd.to_numeric(ranked['ip_fraud_score'], errors='coerce').fillna(-1)
                    ranked = ranked.sort_values(by='ip_fraud_score_num', ascending=False)

                summary['top_records'] = ranked[columns].head(10).fillna('').to_dict(orient='records')

        except Exception:
            pass

    if features_path.exists():
        try:
            fdf = pd.read_csv(features_path)
            summary['feature_rows'] = int(len(fdf))
        except Exception:
            pass

    if capture_log_path.exists():
        try:
            summary['log_preview'] = capture_log_path.read_text(encoding='utf-8', errors='replace')
        except Exception:
            pass

    return render_template('review_logs.html', summary=summary)


@app.post('/api/start-capture')
def start_capture():
    if not FYP_SCRIPT.exists():
        return jsonify({'ok': False, 'message': f'fyp1.py not found at {FYP_SCRIPT}'}), 400

    pcap_name = _safe_name(request.form.get('pcap_file'), 'capture_live.pcap')
    seconds = request.form.get('seconds', '60').strip() or '60'
    features_name = _safe_name(request.form.get('features_csv'), 'features.csv')

    try:
        seconds_int = max(1, int(seconds))
    except ValueError:
        return jsonify({'ok': False, 'message': 'Seconds must be a whole number.'}), 400

    log_name = 'capture_live.txt'

    args = [
        sys.executable,
        str(FYP_SCRIPT),
        '-t',
        str(seconds_int),
        '-o',
        pcap_name,
        '--features-csv',
        features_name,
        '--log',
        log_name,
    ]

    result = _run_command(args)
    ok = result.returncode == 0

    return jsonify(
        {
            'ok': ok,
            'message': 'Capture completed.' if ok else 'Capture failed.',
            'stdout': result.stdout,
            'stderr': result.stderr,
            'outputs': {
                'pcap': pcap_name,
                'features_csv': features_name,
                'log': log_name,
                'scores_csv': 'scores.csv',
            },
        }
    ), (200 if ok else 500)


@app.post('/api/score')
def score_only():
    features_name = _safe_name(request.form.get('features_csv'), 'features.csv')
    scored_name = _safe_name(request.form.get('scored_csv'), 'scores.csv')
    source_path = DATA_DIR / features_name

    if not source_path.exists():
        return jsonify({'ok': False, 'message': f'{features_name} does not exist.'}), 400

    if not MODEL_PATH.exists():
        return jsonify({'ok': False, 'message': f'Model not found at {MODEL_PATH}'}), 400

    try:
        module = _load_fyp1_module()
        temp_scores = DATA_DIR / 'scores.csv'
        module.run_ml_detection(str(MODEL_PATH), str(source_path), str(temp_scores))

        class Args:
            scores_csv = str(temp_scores)
            scamalytics_user = None
            scamalytics_key = None

        module.score_packet(Args())

        final_output = DATA_DIR / 'scores.csv'
        if scored_name != 'scores.csv' and final_output.exists():
            target = DATA_DIR / scored_name
            if target.exists():
                target.unlink()
            final_output.replace(target)
            final_output = target

        return jsonify(
            {
                'ok': True,
                'message': 'Scoring completed.',
                'stdout': f'Scored file created: {final_output.name}',
                'stderr': '',
                'outputs': {
                    'features_csv': features_name,
                    'scores_csv': final_output.name,
                },
            }
        )
    except Exception as exc:
        return jsonify({'ok': False, 'message': 'Scoring failed.', 'stdout': '', 'stderr': str(exc)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
