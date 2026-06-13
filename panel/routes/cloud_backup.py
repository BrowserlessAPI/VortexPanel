from flask import Blueprint, jsonify, request, session
import os, json, threading, uuid, time

cloud_backup_bp = Blueprint('cloud_backup', __name__)
def req(): return 'user' in session

CONFIG_FILE = '/opt/vortexpanel/cloud_backup_config.json'
BACKUP_DIR  = '/opt/vortexpanel/backups'

_jobs = {}

PROVIDER_ENDPOINTS = {
    'aws':     None,
    'b2':      'https://s3.{region}.backblazeb2.com',
    'wasabi':  'https://s3.{region}.wasabisys.com',
    'spaces':  'https://{region}.digitaloceanspaces.com',
    'custom':  None,
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f: return json.load(f)
        except: pass
    return {}

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE,'w') as f: json.dump(cfg, f, indent=2)

def get_client(cfg):
    import boto3
    endpoint = cfg.get('endpoint_url') or ''
    if not endpoint and cfg.get('provider') in PROVIDER_ENDPOINTS:
        tmpl = PROVIDER_ENDPOINTS.get(cfg.get('provider'))
        if tmpl:
            endpoint = tmpl.format(region=cfg.get('region','us-east-1'))
    kwargs = dict(
        aws_access_key_id=cfg.get('access_key'),
        aws_secret_access_key=cfg.get('secret_key'),
        region_name=cfg.get('region','us-east-1'),
    )
    if endpoint:
        kwargs['endpoint_url'] = endpoint
    return boto3.client('s3', **kwargs)

@cloud_backup_bp.route('/api/backups/cloud/config')
def get_config():
    if not req(): return jsonify({'ok':False}),401
    cfg = load_config()
    safe = dict(cfg)
    if safe.get('secret_key'): safe['secret_key'] = '••••••••'
    if safe.get('access_key') and len(safe['access_key'])>4:
        safe['access_key'] = safe['access_key'][:4]+'••••••••'
    return jsonify({'ok':True, 'config':safe, 'connected': bool(cfg.get('bucket'))})

@cloud_backup_bp.route('/api/backups/cloud/config', methods=['PUT'])
def save_cloud_config():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    cfg = load_config()
    for k in ['provider','access_key','secret_key','bucket','region','endpoint_url','auto_upload']:
        v = d.get(k)
        if v is not None and v != '••••••••' and not (k=='access_key' and v.endswith('••••••••')):
            cfg[k] = v.strip() if isinstance(v,str) else v
    if not cfg.get('bucket') or not cfg.get('access_key'):
        return jsonify({'ok':False,'error':'Bucket and access key are required'}),400
    # Test connection
    try:
        client = get_client(cfg)
        client.head_bucket(Bucket=cfg['bucket'])
    except Exception as e:
        return jsonify({'ok':False,'error':f'Connection test failed: {e}'}),400
    save_config(cfg)
    return jsonify({'ok':True})

@cloud_backup_bp.route('/api/backups/cloud/config', methods=['DELETE'])
def disconnect_cloud():
    if not req(): return jsonify({'ok':False}),401
    if os.path.exists(CONFIG_FILE): os.remove(CONFIG_FILE)
    return jsonify({'ok':True})

@cloud_backup_bp.route('/api/backups/cloud/list')
def list_cloud_backups():
    if not req(): return jsonify({'ok':False}),401
    cfg = load_config()
    if not cfg.get('bucket'): return jsonify({'ok':False,'error':'Not configured'}),400
    try:
        client = get_client(cfg)
        prefix = cfg.get('prefix','vortexpanel-backups/')
        resp = client.list_objects_v2(Bucket=cfg['bucket'], Prefix=prefix)
        items = []
        for obj in resp.get('Contents', []):
            items.append({
                'name': obj['Key'].replace(prefix,'',1),
                'key': obj['Key'],
                'size': obj['Size'],
                'modified': obj['LastModified'].isoformat(),
            })
        items.sort(key=lambda x: x['modified'], reverse=True)
        return jsonify({'ok':True, 'items':items})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500

def _do_upload(job_id, local_path, key, cfg):
    try:
        client = get_client(cfg)
        _jobs[job_id] = {'status':'uploading','progress':0}
        client.upload_file(local_path, cfg['bucket'], key)
        _jobs[job_id] = {'status':'done','progress':100}
    except Exception as e:
        _jobs[job_id] = {'status':'error','error':str(e)}

@cloud_backup_bp.route('/api/backups/cloud/upload/<name>', methods=['POST'])
def upload_to_cloud(name):
    if not req(): return jsonify({'ok':False}),401
    cfg = load_config()
    if not cfg.get('bucket'): return jsonify({'ok':False,'error':'Cloud storage not configured'}),400
    local_path = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(local_path):
        return jsonify({'ok':False,'error':'Local backup not found'}),404
    prefix = cfg.get('prefix','vortexpanel-backups/')
    key = prefix + name
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {'status':'starting','progress':0}
    threading.Thread(target=_do_upload, args=(job_id, local_path, key, cfg), daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id})

@cloud_backup_bp.route('/api/backups/cloud/job/<job_id>')
def cloud_job_status(job_id):
    if not req(): return jsonify({'ok':False}),401
    return jsonify({'ok':True, **_jobs.get(job_id, {'status':'unknown'})})

@cloud_backup_bp.route('/api/backups/cloud/download/<name>', methods=['POST'])
def download_from_cloud(name):
    if not req(): return jsonify({'ok':False}),401
    cfg = load_config()
    if not cfg.get('bucket'): return jsonify({'ok':False,'error':'Not configured'}),400
    prefix = cfg.get('prefix','vortexpanel-backups/')
    key = prefix + name
    os.makedirs(BACKUP_DIR, exist_ok=True)
    local_path = os.path.join(BACKUP_DIR, name)
    try:
        client = get_client(cfg)
        client.download_file(cfg['bucket'], key, local_path)
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500

@cloud_backup_bp.route('/api/backups/cloud/<name>', methods=['DELETE'])
def delete_cloud_backup(name):
    if not req(): return jsonify({'ok':False}),401
    cfg = load_config()
    if not cfg.get('bucket'): return jsonify({'ok':False,'error':'Not configured'}),400
    prefix = cfg.get('prefix','vortexpanel-backups/')
    key = prefix + name
    try:
        client = get_client(cfg)
        client.delete_object(Bucket=cfg['bucket'], Key=key)
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500
