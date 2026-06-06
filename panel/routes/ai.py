from flask import Blueprint, jsonify, request, session, Response
import json, os, urllib.request, urllib.error

ai_bp = Blueprint('ai', __name__)
def req(): return 'user' in session

CONFIG_FILE = '/opt/vortexpanel/ai_config.json'

# Default NeonCodex config
DEFAULT_CONFIG = {
    'enabled':    True,
    'api_key':    '',
    'base_url':   'https://neoncodex.io/api/v1',
    'model':      'neoncodex-default',
    'max_tokens': 2048,
    'name':       'NeonCodex AI',
}

SYSTEM_PROMPT = """You are VortexPanel AI Assistant, powered by NeonCodex AI.
You are a server management expert integrated directly into VortexPanel — a Linux server control panel.

Your capabilities:
- Explain server errors, nginx/apache configs, PHP errors
- Generate nginx/apache/caddy config blocks
- Diagnose server issues (disk, CPU, memory, processes)
- Explain shell commands and suggest fixes
- Help with MySQL/PostgreSQL queries
- Review and fix PHP, Python, Node.js code
- Guide users through server hardening

Always be concise and practical. Format code blocks with proper markdown.
When given server context (logs, configs), analyze them specifically.
Never suggest destructive commands without clear warnings."""

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                saved = json.load(f)
            return {**DEFAULT_CONFIG, **saved}
        except: pass
    return dict(DEFAULT_CONFIG)

def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

@ai_bp.route('/api/ai/config')
def get_config():
    if not req(): return jsonify({'ok': False}), 401
    cfg = load_config()
    safe = {k: ('***' if k == 'api_key' and v else v) for k, v in cfg.items()}
    return jsonify({'ok': True, 'config': safe})

@ai_bp.route('/api/ai/config', methods=['PUT'])
def save_ai_config():
    if not req(): return jsonify({'ok': False}), 401
    d   = request.get_json() or {}
    cfg = load_config()
    for key in ['enabled', 'api_key', 'base_url', 'model', 'max_tokens', 'name']:
        if key in d and d[key] != '***':
            cfg[key] = d[key]
    save_config(cfg)
    return jsonify({'ok': True})

@ai_bp.route('/api/ai/models')
def list_models():
    if not req(): return jsonify({'ok': False}), 401
    cfg = load_config()
    # Try to fetch models from NeonCodex API
    try:
        url  = cfg['base_url'].rstrip('/') + '/models'
        req2 = urllib.request.Request(url)
        req2.add_header('Authorization', f'Bearer {cfg["api_key"]}')
        req2.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req2, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            models = data.get('data', data.get('models', []))
            return jsonify({'ok': True, 'models': models})
    except Exception as e:
        # Return default NeonCodex models list
        return jsonify({'ok': True, 'models': [
            {'id': 'neoncodex-default', 'name': 'NeonCodex Default'},
        ], 'error': str(e)})

@ai_bp.route('/api/ai/chat', methods=['POST'])
def chat():
    if not req(): return jsonify({'ok': False}), 401
    cfg = load_config()
    if not cfg.get('api_key'):
        return jsonify({'ok': False, 'error': 'NeonCodex API key not configured. Go to Settings → AI Assistant to set it up.'}), 400
    if not cfg.get('enabled'):
        return jsonify({'ok': False, 'error': 'AI Assistant is disabled. Enable it in Settings → AI Assistant.'}), 400

    d        = request.get_json() or {}
    messages = d.get('messages', [])
    context  = d.get('context', '')   # extra server context injected automatically

    if not messages:
        return jsonify({'ok': False, 'error': 'No messages provided'}), 400

    # Build full message list
    system_content = SYSTEM_PROMPT
    if context:
        system_content += f'\n\n## Current Server Context\n{context}'

    payload = {
        'model':      cfg['model'],
        'messages':   [{'role': 'system', 'content': system_content}] + messages,
        'max_tokens': int(cfg.get('max_tokens', 2048)),
        'stream':     False,
    }

    try:
        url  = cfg['base_url'].rstrip('/') + '/chat/completions'
        body = json.dumps(payload).encode()
        req2 = urllib.request.Request(url, data=body, method='POST')
        req2.add_header('Authorization', f'Bearer {cfg["api_key"]}')
        req2.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req2, timeout=60) as resp:
            data = json.loads(resp.read().decode())
        content = data['choices'][0]['message']['content']
        return jsonify({'ok': True, 'content': content, 'model': cfg['model']})
    except urllib.error.HTTPError as e:
        try: err = json.loads(e.read().decode())
        except: err = {'error': str(e)}
        return jsonify({'ok': False, 'error': err.get('error', {}).get('message', str(e))}), 400
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@ai_bp.route('/api/ai/quick', methods=['POST'])
def quick_action():
    """Pre-built quick actions for specific panel contexts"""
    if not req(): return jsonify({'ok': False}), 401
    d      = request.get_json() or {}
    action = d.get('action', '')
    data   = d.get('data', '')

    prompts = {
        'explain_code':    f'Explain this code concisely and identify any issues:\n\n```\n{data}\n```',
        'fix_code':        f'Fix any bugs or errors in this code. Return only the corrected code with brief inline comments:\n\n```\n{data}\n```',
        'explain_error':   f'Explain this server error and how to fix it:\n\n```\n{data}\n```',
        'nginx_config':    f'Generate a production-ready Nginx server block config for: {data}\nInclude SSL placeholder, gzip, security headers.',
        'explain_command': f'Explain what this command does step by step:\n\n```bash\n{data}\n```',
        'diagnose_log':    f'Analyze this server log and identify the root cause of any errors:\n\n```\n{data}\n```',
        'optimize_query':  f'Review and optimize this SQL query:\n\n```sql\n{data}\n```',
        'php_config':      f'Suggest optimal php.ini settings for a production WordPress/PHP site given: {data}',
        'security_audit':  f'Review this config for security issues and suggest hardening:\n\n```\n{data}\n```',
        'cron_schedule':   f'Help me write a cron job for: {data}. Show the cron expression and the command.',
    }

    prompt = prompts.get(action)
    if not prompt:
        return jsonify({'ok': False, 'error': 'Unknown action'}), 400

    # Delegate to chat directly
    cfg = load_config()
    if not cfg.get('api_key'):
        return jsonify({'ok': False, 'error': 'NeonCodex API key not configured.'}), 400

    system_content = SYSTEM_PROMPT
    payload = {
        'model':      cfg['model'],
        'messages':   [{'role': 'system', 'content': system_content},
                       {'role': 'user',   'content': prompt}],
        'max_tokens': int(cfg.get('max_tokens', 2048)),
        'stream':     False,
    }
    try:
        url  = cfg['base_url'].rstrip('/') + '/chat/completions'
        body = json.dumps(payload).encode()
        req2 = urllib.request.Request(url, data=body, method='POST')
        req2.add_header('Authorization', f'Bearer {cfg["api_key"]}')
        req2.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req2, timeout=60) as resp:
            data = json.loads(resp.read().decode())
        content = data['choices'][0]['message']['content']
        return jsonify({'ok': True, 'content': content})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
