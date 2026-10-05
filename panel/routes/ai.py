from flask import Blueprint, jsonify, request
import json, os, urllib.request, urllib.error

ai_bp = Blueprint('ai', __name__)
def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()

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
    # 0600: holds the API key (was written world-readable).
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    tmp = CONFIG_FILE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)


def _err_message(err, fallback):
    """Provider error bodies are {'error': {'message': ...}} or {'error': '...'}
    or {'message': ...}; the old .get('error', {}).get(...) crashed (500) on
    the string form."""
    if isinstance(err, dict):
        e = err.get('error')
        if isinstance(e, dict):
            return str(e.get('message') or fallback)
        if e:
            return str(e)
        if err.get('message'):
            return str(err['message'])
    return fallback


def _post_chat(cfg, payload):
    url = cfg['base_url'].rstrip('/') + '/chat/completions'
    req2 = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST')
    req2.add_header('Authorization', f'Bearer {cfg["api_key"]}')
    req2.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req2, timeout=90) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try: err = json.loads(e.read().decode())
        except Exception: err = None
        return None, _err_message(err, f'HTTP {e.code}: {e.reason}')
    except Exception as e:
        return None, str(e)
    try:
        return data['choices'][0]['message']['content'], None
    except Exception:
        return None, _err_message(data, 'Unexpected response from the AI provider')

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
    # base_url is fetched server-side as root: only http(s), never file:// etc.
    if not str(cfg.get('base_url', '')).lower().startswith(('https://', 'http://')):
        return jsonify({'ok': False, 'error': 'API base URL must start with https://'}), 400
    try:
        cfg['max_tokens'] = max(1, min(200000, int(cfg.get('max_tokens', 2048))))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'max_tokens must be a number'}), 400
    save_config(cfg)
    return jsonify({'ok': True})

@ai_bp.route('/api/ai/models')
def list_models():
    if not req(): return jsonify({'ok': False}), 401
    cfg = load_config()
    # Try to fetch models from NeonCodex API
    if not str(cfg.get('base_url', '')).lower().startswith(('https://', 'http://')):
        return jsonify({'ok': True, 'models': [{'id': 'neoncodex-default', 'name': 'NeonCodex Default'}],
                        'error': 'Invalid API base URL'})
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

    if not messages or not isinstance(messages, list):
        return jsonify({'ok': False, 'error': 'No messages provided'}), 400
    if not str(cfg.get('base_url', '')).lower().startswith(('https://', 'http://')):
        return jsonify({'ok': False, 'error': 'Invalid API base URL in AI settings'}), 400

    # Build full message list
    system_content = SYSTEM_PROMPT
    if context:
        system_content += f'\n\n## Current Server Context\n{context}'

    try:
        max_tokens = int(cfg.get('max_tokens', 2048))
    except (TypeError, ValueError):
        max_tokens = 2048
    payload = {
        'model':      cfg['model'],
        'messages':   [{'role': 'system', 'content': system_content}] + messages,
        'max_tokens': max_tokens,
        'stream':     False,
    }
    content, error = _post_chat(cfg, payload)
    if error is not None:
        return jsonify({'ok': False, 'error': error}), 502
    return jsonify({'ok': True, 'content': content, 'model': cfg['model']})

@ai_bp.route('/api/ai/quick', methods=['POST'])
def quick_action():
    """Pre-built quick actions for specific panel contexts"""
    if not req(): return jsonify({'ok': False}), 401
    cfg = load_config()
    if not cfg.get('enabled'):
        return jsonify({'ok': False, 'error': 'AI assistant is disabled'}), 400
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

    if not str(cfg.get('base_url', '')).lower().startswith(('https://', 'http://')):
        return jsonify({'ok': False, 'error': 'Invalid API base URL in AI settings'}), 400
    system_content = SYSTEM_PROMPT
    try:
        max_tokens = int(cfg.get('max_tokens', 2048))
    except (TypeError, ValueError):
        max_tokens = 2048
    payload = {
        'model':      cfg['model'],
        'messages':   [{'role': 'system', 'content': system_content},
                       {'role': 'user',   'content': prompt}],
        'max_tokens': max_tokens,
        'stream':     False,
    }
    content, error = _post_chat(cfg, payload)
    if error is not None:
        return jsonify({'ok': False, 'error': error}), 502
    return jsonify({'ok': True, 'content': content})
