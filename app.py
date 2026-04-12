from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, List

import pandas as pd
from flask import Flask, jsonify, render_template, request, Response, send_file

from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent / 'packet-header_n_frame-analysis'
FYP_SCRIPT = PROJECT_ROOT / 'fyp1.py'
DATA_DIR = PROJECT_ROOT
MODEL_PATH = DATA_DIR / 'random_forest' / 'rf_model.joblib'

app = Flask(__name__, template_folder='templates', static_folder='static')
app.json.sort_keys = False


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


def get_existing_cols(df, cols):
    return [c for c in cols if c in df.columns]


def get_paginated_csv_response(csv_path: Path, page: int, per_page: int):
    if not csv_path.exists():
        return jsonify({
            'data': [],
            'columns': [],
            'total': 0,
            'page': page,
            'per_page': per_page
        })

    df = pd.read_csv(csv_path)
    columns = list(df.columns)

    start = (page - 1) * per_page
    end = start + per_page

    data = df.iloc[start:end][columns].fillna('').to_dict(orient='records')

    return jsonify({
        'data': data,
        'columns': columns,
        'total': int(len(df)),
        'page': page,
        'per_page': per_page
    })


def generate_filename(base_name: str, ext: str):
    now = datetime.now()
    timestamp = now.strftime('%Y%m%d_%H%M')
    return f"{timestamp}_{base_name}.{ext}"


def csv_download_response(df: pd.DataFrame, base_name: str):
    filename = generate_filename(base_name, 'csv')

    csv_data = df.to_csv(index=False)

    return Response(
        csv_data,
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/review-logs')
def review_logs():
    scores_path = DATA_DIR / 'scores.csv'
    features_path = DATA_DIR / 'features.csv'
    capture_log_path = DATA_DIR / 'capture_live.txt'
    flows_path = DATA_DIR / 'flows.csv'

    summary = {
        'total_rows': 0,
        'labels': {},
        'risk_levels': {},
        'score_avg': None,
        'top_records': [],
        'feature_rows': 0,
        'log_preview': '',
        'flow_rows': 0,
        'top_flows': [],
        'flow_risk_levels': {},
        'protocol_evidence': [],
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

    if flows_path.exists():
        try:
            flow_df = pd.read_csv(flows_path)
            summary['flow_rows'] = int(len(flow_df))

            if 'flow_risk_level' in flow_df.columns:
                summary['flow_risk_levels'] = {
                    str(k): int(v)
                    for k, v in flow_df['flow_risk_level'].fillna('unknown').value_counts().to_dict().items()
                }

            flow_cols = [c for c in [
                'flow_src_ip', 
                'flow_dst_ip', 
                'flow_proto',
                'flow_src_port', 
                'flow_dst_port',
                'flow_pkts', 
                'flow_duration',
                'flow_protocol_hint',

                'flow_http_detect_source',
                'flow_http_method',
                'flow_http_host',
                'flow_http_path',

                'flow_tls_detect_source',
                'flow_tls_sni',

                'flow_risk_score',
                'flow_risk_level',
                'flow_risk_reason'
            ] if c in flow_df.columns]

            if flow_cols:
                ranked_flows = flow_df.copy()

                ranked_flows['flow_risk_score_num'] = pd.to_numeric(
                    ranked_flows['flow_risk_score'], errors='coerce'
                ).fillna(-1)

                ranked_flows = ranked_flows.sort_values(
                    by='flow_risk_score_num', ascending=False
                )

                summary['top_flows'] = ranked_flows[flow_cols].head(10).fillna('').to_dict(orient='records')

                protocol_cols = [c for c in [
                    'flow_src_ip',
                    'flow_dst_ip',
                    'flow_src_port',
                    'flow_dst_port',
                    'flow_protocol_hint',

                    'flow_http_detect_source',
                    'flow_http_method',
                    'flow_http_host',
                    'flow_http_path',

                    'flow_tls_detect_source',
                    'flow_tls_sni',

                    'flow_ssh_seen',

                    'flow_risk_score',
                    'flow_risk_level',
                ] if c in flow_df.columns]

                if protocol_cols:
                    protocol_df = flow_df.copy()

                    if 'flow_risk_score' in protocol_df.columns:
                        protocol_df['flow_risk_score_num'] = pd.to_numeric(
                            protocol_df['flow_risk_score'], errors='coerce'
                        ).fillna(-1)

                        protocol_df = protocol_df.sort_values(
                            by='flow_risk_score_num', ascending=False
                        )

                    # keep only rows that actually contain HTTP/TLS evidence
                    protocol_df = protocol_df[
                        (
                            protocol_df.get('flow_http_method', '').fillna('').astype(str).str.strip() != ''
                        ) |
                        (
                            protocol_df.get('flow_http_host', '').fillna('').astype(str).str.strip() != ''
                        ) |
                        (
                            protocol_df.get('flow_tls_sni', '').fillna('').astype(str).str.strip() != ''
                        ) |
                        (
                            protocol_df.get('flow_http_detect_source', '').fillna('').astype(str).str.strip() != ''
                        ) |
                        (
                            protocol_df.get('flow_tls_detect_source', '').fillna('').astype(str).str.strip() != ''
                        ) |
                        (
                            pd.to_numeric(protocol_df.get('flow_ssh_seen', 0), errors='coerce').fillna(0) > 0
                        ) |
                        (
                            protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.strip().str.lower() == 'ssh'
                        )
                    ]

                    # summary['protocol_evidence'] = protocol_df[protocol_cols].head(10).fillna('').to_dict(orient='records')

        except Exception:
            pass

    return render_template('review_logs.html', summary=summary)


@app.post('/api/start-capture')
def start_capture():
    if not FYP_SCRIPT.exists():
        return jsonify({'ok': False, 'message': f'fyp1.py not found at {FYP_SCRIPT}'}), 400

    pcap_name = "capture_live.pcap"
    seconds = request.form.get('seconds', '60').strip() or '60'
    features_name = "features.csv"
    flows_csv = "flows.csv"

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
                'flows_csv': flows_csv,
            },
        }
    ), (200 if ok else 500)


@app.post('/api/score')
def score_only():
    features_name = 'features.csv'
    scored_name = 'scores.csv'
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


@app.get('/api/records')
def get_records():
    page = max(1, int(request.args.get('page', 1)))
    per_page = 50
    return get_paginated_csv_response(DATA_DIR / 'scores.csv', page, per_page)


@app.get('/api/flows')
def get_flows():
    page = max(1, int(request.args.get('page', 1)))
    per_page = 50
    return get_paginated_csv_response(DATA_DIR / 'flows.csv', page, per_page)


@app.get('/api/protocol-evidence')
def get_protocol_evidence():
    protocol = request.args.get('protocol', 'all').strip().lower()
    detect_source = request.args.get('detect_source', 'all').strip().lower()
    risk_sort = request.args.get('risk_sort', 'desc').strip().lower()
    
    page = max(1, int(request.args.get('page', 1)))
    per_page = 9

    flows_path = DATA_DIR / 'flows.csv'

    if not flows_path.exists():
        return jsonify({
            'data': [],
            'columns': [],
            'total': 0,
            'page': page,
            'per_page': per_page
        })

    df = pd.read_csv(flows_path)

    protocol_cols = [c for c in [
        'flow_src_ip',
        'flow_dst_ip',
        'flow_src_port',
        'flow_dst_port',
        'flow_protocol_hint',

        'flow_http_detect_source',
        'flow_http_method',
        'flow_http_host',
        'flow_http_path',

        'flow_tls_detect_source',
        'flow_tls_sni',

        'flow_ssh_seen',
        'flow_ssh_payload_detected',
        'flow_ssh_port_fallback',
        'flow_ssh_detect_source',
        'flow_ssh_banner',

        'flow_smb_seen',
        'flow_smb_payload_detected',
        'flow_smb_port_fallback',
        'flow_smb_detect_source',
        'flow_smb_version',

        'flow_risk_score',
        'flow_risk_level',
    ] if c in df.columns]

    protocol_df = df.copy()

    # sort by risk
    protocol_df['flow_risk_score_num'] = pd.to_numeric(
        protocol_df.get('flow_risk_score', 0),
        errors='coerce'
    ).fillna(-1)

    ascending = True if risk_sort == 'asc' else False

    protocol_df = protocol_df.sort_values(
        by='flow_risk_score_num',
        ascending=ascending
    )

    # base evidence filter
    protocol_df = protocol_df[
        (
            protocol_df.get('flow_http_method', '').fillna('').astype(str).str.strip() != ''
        ) |
        (
            protocol_df.get('flow_http_host', '').fillna('').astype(str).str.strip() != ''
        ) |
        (
            protocol_df.get('flow_tls_sni', '').fillna('').astype(str).str.strip() != ''
        ) |
        (
            pd.to_numeric(protocol_df.get('flow_ssh_payload_detected', 0), errors='coerce').fillna(0) > 0
        ) |
        (
            pd.to_numeric(protocol_df.get('flow_smb_payload_detected', 0), errors='coerce').fillna(0) > 0
        ) |
        (
            protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.strip().str.lower().isin(['http', 'tls', 'ssh', 'smb'])
        )
    ]

    # protocol-specific filter
    if protocol == 'http':
        protocol_df = protocol_df[
            (
                protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.strip().str.lower() == 'http'
            ) |
            (
                protocol_df.get('flow_http_method', '').fillna('').astype(str).str.strip() != ''
            ) |
            (
                protocol_df.get('flow_http_host', '').fillna('').astype(str).str.strip() != ''
            )
        ]

    elif protocol == 'tls':
        protocol_df = protocol_df[
            (
                protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.strip().str.lower() == 'tls'
            ) |
            (
                protocol_df.get('flow_tls_sni', '').fillna('').astype(str).str.strip() != ''
            ) |
            (
                protocol_df.get('flow_tls_detect_source', '').fillna('').astype(str).str.strip() != ''
            )
        ]

    elif protocol == 'ssh':
        protocol_df = protocol_df[
            (
                protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.strip().str.lower() == 'ssh'
            ) |
            (
                pd.to_numeric(protocol_df.get('flow_ssh_seen', 0), errors='coerce').fillna(0) > 0
            ) |
            (
                pd.to_numeric(protocol_df.get('flow_ssh_payload_detected', 0), errors='coerce').fillna(0) > 0
            )
        ]

    elif protocol == 'smb':
        protocol_df = protocol_df[
            (
                protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.strip().str.lower() == 'smb'
            ) |
            (
                pd.to_numeric(protocol_df.get('flow_smb_seen', 0), errors='coerce').fillna(0) > 0
            ) |
            (
                pd.to_numeric(protocol_df.get('flow_smb_payload_detected', 0), errors='coerce').fillna(0) > 0
            )
        ]
    
    # detection source filter
    if detect_source == 'payload':
        protocol_df = protocol_df[
            (
                protocol_df.get('flow_http_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'payload'
            ) |
            (
                protocol_df.get('flow_tls_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'payload'
            ) |
            (
                protocol_df.get('flow_ssh_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'payload'
            ) |
            (
                protocol_df.get('flow_smb_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'payload'
            )
        ]

    elif detect_source == 'port':
        protocol_df = protocol_df[
            (
                protocol_df.get('flow_http_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'port'
            ) |
            (
                protocol_df.get('flow_tls_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'port'
            ) |
            (
                protocol_df.get('flow_ssh_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'port'
            ) |
            (
                protocol_df.get('flow_smb_detect_source', '').fillna('').astype(str).str.strip().str.lower() == 'port'
            )
        ]

    total = len(protocol_df)

    start = (page - 1) * per_page
    end = start + per_page

    data = protocol_df.iloc[start:end][protocol_cols].fillna('').to_dict(orient='records')

    return jsonify({
        'data': data,
        'columns': protocol_cols,
        'total': int(total),
        'page': page,
        'per_page': per_page
    })


@app.get('/api/export/top-packets')
def export_top_packets():
    scores_path = DATA_DIR / 'scores.csv'

    if not scores_path.exists():
        return jsonify({'message': 'scores.csv not found'}), 404

    df = pd.read_csv(scores_path)

    if 'ip_fraud_score' in df.columns:
        df['ip_fraud_score_num'] = pd.to_numeric(df['ip_fraud_score'], errors='coerce').fillna(-1)
        df = df.sort_values(by='ip_fraud_score_num', ascending=False)

    export_cols = [c for c in ['frame_no', 'ip_src', 'ip_dst', 'label', 'ip_fraud_score_display', 'risk_level'] if c in df.columns]
    df = df[export_cols].head(10).fillna('')
    
    return csv_download_response(df, 'top_10_highest_risk_packets')


@app.get('/api/export/top-flows')
def export_top_flows():
    flows_path = DATA_DIR / 'flows.csv'

    if not flows_path.exists():
        return jsonify({'message': 'flows.csv not found'}), 404

    df = pd.read_csv(flows_path)

    df['flow_risk_score_num'] = pd.to_numeric(df.get('flow_risk_score', 0), errors='coerce').fillna(-1)
    df = df.sort_values(by='flow_risk_score_num', ascending=False)

    export_cols = [c for c in [
        'flow_src_ip',
        'flow_dst_ip',
        'flow_proto',
        'flow_src_port',
        'flow_dst_port',
        'flow_pkts',
        'flow_duration',
        'flow_protocol_hint',
        'flow_http_detect_source',
        'flow_http_method',
        'flow_http_host',
        'flow_http_path',
        'flow_tls_detect_source',
        'flow_tls_sni',
        'flow_risk_score',
        'flow_risk_level',
        'flow_risk_reason'
    ] if c in df.columns]

    df = df[export_cols].head(10).fillna('')

    return csv_download_response(df, 'top_10_highest_risk_flows')


@app.get('/api/export/records')
def export_records():
    scores_path = DATA_DIR / 'scores.csv'

    if not scores_path.exists():
        return jsonify({'message': 'scores.csv not found'}), 404

    df = pd.read_csv(scores_path).fillna('')
    return csv_download_response(df, 'all_scored_records')


@app.get('/api/export/flows')
def export_all_flows():
    flows_path = DATA_DIR / 'flows.csv'

    if not flows_path.exists():
        return jsonify({'message': 'flows.csv not found'}), 404

    df = pd.read_csv(flows_path).fillna('')
    
    return csv_download_response(df, 'all_flow_records')


@app.get('/api/export/capture-log')
def export_capture_log():
    log_path = DATA_DIR / 'capture_live.txt'

    if not log_path.exists():
        return jsonify({'message': 'capture_live.txt not found'}), 404

    content = log_path.read_text(encoding='utf-8', errors='replace')

    filename = generate_filename('capture_log_preview', 'txt')

    return Response(
        content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
)


@app.get('/api/export/capture-log-pcap')
def export_capture_log_pcap():
    pcap_path = DATA_DIR / 'capture_live.pcap'

    if not pcap_path.exists():
        return jsonify({'message': 'capture_live.pcap not found'}), 404
    
    filename = generate_filename('capture_live', 'pcap')

    return send_file(
        pcap_path,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.tcpdump.pcap'
    )


@app.get('/api/export/protocol-evidence')
def export_protocol_evidence():
    protocol = request.args.get('protocol', 'all').strip().lower()
    detect_source = request.args.get('detect_source', 'all').strip().lower()
    risk_sort = request.args.get('risk_sort', 'desc').strip().lower()

    flows_path = DATA_DIR / 'flows.csv'

    if not flows_path.exists():
        return jsonify({'message': 'flows.csv not found'}), 404

    df = pd.read_csv(flows_path)
    protocol_df = df.copy()

    protocol_df['flow_risk_score_num'] = pd.to_numeric(
        protocol_df.get('flow_risk_score', 0),
        errors='coerce'
    ).fillna(-1)

    ascending = True if risk_sort == 'asc' else False
    protocol_df = protocol_df.sort_values(by='flow_risk_score_num', ascending=ascending)

    # keep rows that have protocol evidence
    protocol_df = protocol_df[
        (
            protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.strip() != ''
        )
    ]

    # filter by protocol
    if protocol != 'all':
        protocol_df = protocol_df[
            protocol_df.get('flow_protocol_hint', '').fillna('').astype(str).str.lower() == protocol
        ]

    # filter by detect source
    if detect_source != 'all':
        def row_source(row):
            proto = str(row.get('flow_protocol_hint', '')).lower()

            if proto == 'http':
                return str(row.get('flow_http_detect_source', '')).lower()
            if proto == 'tls':
                return str(row.get('flow_tls_detect_source', '')).lower()
            if proto == 'ssh':
                return str(row.get('flow_ssh_detect_source', '')).lower()
            if proto == 'smb':
                return str(row.get('flow_smb_detect_source', '')).lower()

            return ''

        protocol_df = protocol_df[protocol_df.apply(lambda row: row_source(row) == detect_source, axis=1)]

    export_cols = [c for c in [
        'flow_src_ip',
        'flow_dst_ip',
        'flow_src_port',
        'flow_dst_port',
        'flow_protocol_hint',

        'flow_http_detect_source',
        'flow_http_method',
        'flow_http_host',
        'flow_http_path',

        'flow_tls_detect_source',
        'flow_tls_sni',

        'flow_ssh_detect_source',
        'flow_ssh_banner',

        'flow_smb_detect_source',
        'flow_smb_version',

        'flow_risk_score',
        'flow_risk_level',
    ] if c in protocol_df.columns]

    protocol_df = protocol_df[export_cols].fillna('')

    filename = f'protocol_evidence_{protocol}_{detect_source}_{risk_sort}'

    return csv_download_response(protocol_df, filename)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
