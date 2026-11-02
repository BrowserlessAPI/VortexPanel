"""PHP Security rules -> a Snuffleupagus rules file.

Every rule is written with positional arguments (.pos("N")) so the same file works
on PHP 7.4 and PHP 8.x (parameter NAMES changed between them). Modes:
  block  the call is stopped (PHP aborts the request) and logged
  log    the call is only logged (Snuffleupagus simulation mode)
  off    not written
Trusted folders become .allow() lines placed before the blocking lines.
"""
import re

# Where uploaded files land (WordPress, Joomla images, Drupal files, Laravel storage, generic uploads, temp).
# Deliberately NOT bare 'cache', 'image' or 'files': Composer libraries such as symfony/cache
# and intervention/image live in folders with those names.
UPLOAD_DIRS = r'/(wp-content/uploads|uploads?|upload_files|tmp|temp|sites/[^/]+/files|storage/app/public|images/uploads|media/uploads)/'
SHELL_FUNCS = ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec']
PHP_EXT = r'\.(php[0-9]?|phtml|pht|phar|phps|inc)$'

# id, title, description, group, default mode, note about compatibility, can_log (simulation)
RULES = [
    ('webshell', 'Webshells in upload folders',
     'Scripts inside upload and temp folders may not run system commands. Uploaded webshells live there.',
     'Webshells', 'block', 'Safe for WordPress, Joomla, Laravel and most apps.', True),
    ('eval_shell', 'Commands from eval()',
     'Code run through eval() may not call system commands or write files: the classic obfuscated backdoor pattern.',
     'Webshells', 'block', 'Safe: normal code does not run shell commands from eval.', True),
    ('upload_php', 'Uploading PHP files',
     'move_uploaded_file() may not save a file with a PHP extension.',
     'Uploads', 'block', 'Safe unless your site lets users upload PHP plugins/themes through a custom uploader.', True),
    ('write_php_uploads', 'Writing PHP files into upload folders',
     'file_put_contents() may not create .php files inside upload or temp folders.',
     'Uploads', 'block', 'Safe: updates write PHP into plugin folders, not uploads.', True),
    ('remote_include', 'Remote and data:// file inclusion',
     'include/require of http(s)://, ftp://, data:// and expect:// streams is blocked (remote file inclusion).',
     'Inclusion', 'block', 'Safe.', True),
    ('include_ext', 'Including non-PHP files',
     'include/require only accepts .php, .inc and .phtml files, which stops ../../etc/passwd style local file inclusion.',
     'Inclusion', 'log', 'Some template engines include .html or .tpl files; test in log mode first.', True),
    ('cmd_injection', 'Command injection',
     'Shell metacharacters ($ | ; & ` ( ) \\) are refused in system/exec/shell_exec/proc_open/passthru/popen.',
     'Commands', 'log', 'Backup and image plugins sometimes pass "2>&1"; test in log mode first.', True),
    ('readonly_exec', 'Writable PHP files',
     'PHP only runs files that the PHP user cannot write. A dropped or modified file cannot run.',
     'Commands', 'log', 'Breaks sites whose files are owned by the PHP user (common for WordPress auto-updates).', True),
    ('chmod', 'chmod 0777 / 0666',
     'Scripts may not make files writable for everyone.', 'Hardening', 'block', 'Safe.', True),
    ('env', 'LD_PRELOAD / GCONV environment tricks',
     'putenv() of LD_*, GCONV_ and PATH is blocked (known disable_functions bypasses).',
     'Hardening', 'block', 'Safe.', True),
    ('extract', 'extract() of request variables',
     'extract($_GET / $_POST / ...) is blocked: it lets visitors overwrite any variable.', 'Hardening', 'block', 'Safe.', True),
    ('ini_basedir', 'Changing open_basedir at runtime',
     'ini_set("open_basedir") is blocked (a known open_basedir bypass).', 'Hardening', 'block', 'Safe.', True),
    ('recon', 'Backdoor reconnaissance',
     'Logs scripts that test whether exec/system/shell_exec/proc_open/passthru/eval exist (backdoors check before acting).',
     'Hardening', 'log', 'Many legitimate plugins check this too: log mode is recommended.', True),
    ('curl_tls', 'Turning off TLS certificate checks in cURL',
     'curl_setopt() may not disable SSL_VERIFYPEER / SSL_VERIFYHOST, and file:// URLs are refused.',
     'Network', 'log', 'Some old plugins turn verification off; test in log mode first.', True),
    ('mail_params', 'mail() extra parameters',
     'Refuses mail() additional parameters that start with "-" (sendmail argument injection).',
     'Network', 'off', 'Breaks plugins that pass "-f sender@domain"; leave off unless you need it.', True),
    ('xxe', 'XML external entities (XXE)',
     'Disables loading external entities in the XML parser.', 'Network', 'block', 'Safe.', False),
    ('harden_random', 'Strong random numbers',
     'rand() and mt_rand() use the secure random generator.', 'Hardening', 'block', 'Safe.', False),
    ('cookie_samesite', 'SameSite session cookie',
     'The PHPSESSID cookie gets SameSite=Lax (CSRF protection).', 'Hardening', 'block', 'Safe.', False),
]
RULE_IDS = [r[0] for r in RULES]
DEFAULT_MODES = {r[0]: r[4] for r in RULES}


def _q(s):
    """A value inside "..." in the rules file."""
    return str(s).replace('\\', '\\\\').replace('"', '\\"')


def _df(func, tail, mode):
    """One disable_function line in the chosen mode."""
    return f'sp.disable_function.function("{func}"){tail}.drop()' + ('.simulation();' if mode == 'log' else ';')


def _allow_lines(funcs, trusted):
    out = []
    for path in trusted:
        rx = '^' + re.escape(path.rstrip('/')) + '/'
        for f in funcs:
            out.append(f'sp.disable_function.function("{f}").filename_r("{_q(rx)}").allow();')
    return out


def build(modes, trusted=()):
    """Rules file text for these modes {rule: block|log|off} and trusted folders."""
    m = dict(DEFAULT_MODES)
    m.update({k: v for k, v in (modes or {}).items() if k in m and v in ('block', 'log', 'off')})
    trusted = [t for t in (trusted or []) if t.startswith('/')]
    L = ['# Generated by VortexPanel PHP Security. Do not edit: change the rules in the panel.',
         'sp.log_media("syslog");']

    def on(rid):
        return m.get(rid) in ('block', 'log')

    if on('harden_random'):
        L.append('sp.harden_random.enable();')
    if on('xxe'):
        L.append('sp.xxe_protection.enable();')
    if on('cookie_samesite'):
        L.append('sp.cookie.name("PHPSESSID").samesite("lax");')
    if on('readonly_exec'):
        L.append('sp.readonly_exec.simulation().enable();' if m['readonly_exec'] == 'log' else 'sp.readonly_exec.enable();')
    if on('eval_shell'):
        lst = ','.join(SHELL_FUNCS + ['assert', 'create_function', 'file_put_contents', 'fputs', 'chmod',
                                      'move_uploaded_file', 'fsockopen'])
        L.append(f'sp.eval_blacklist.list("{lst}")' + ('.simulation();' if m['eval_shell'] == 'log' else ';'))

    # trusted folders first: an .allow() match ends the evaluation for that call
    used = set()
    if on('webshell') or on('cmd_injection'):
        used.update(SHELL_FUNCS)
    if on('upload_php'):
        used.add('move_uploaded_file')
    if on('write_php_uploads'):
        used.add('file_put_contents')
    if on('include_ext') or on('remote_include'):
        used.update(['include', 'include_once', 'require', 'require_once'])
    L += _allow_lines(sorted(used), trusted)

    if on('webshell'):
        for f in SHELL_FUNCS:
            L.append(_df(f, f'.filename_r("{_q(UPLOAD_DIRS)}").alias("command from a script in an upload folder")', m['webshell']))
    if on('cmd_injection'):
        for f in ('system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open'):
            L.append(_df(f, '.pos("0").value_r("[$|;&`\\\\n\\\\(\\\\)\\\\\\\\]").alias("shell metacharacters in a command")', m['cmd_injection']))
    if on('upload_php'):
        L.append(_df('move_uploaded_file', f'.pos("1").value_r("{_q(PHP_EXT)}").alias("PHP file upload")', m['upload_php']))
    if on('write_php_uploads'):
        L.append(_df('file_put_contents', f'.pos("0").value_r("{_q(UPLOAD_DIRS[:-1] + ".*" + PHP_EXT)}").alias("PHP file written into an upload folder")',
                     m['write_php_uploads']))
    incs = ['include', 'include_once', 'require', 'require_once']
    if on('remote_include'):
        for f in incs:
            L.append(_df(f, '.value_r("^(https?|ftp|data|expect)://").alias("remote file inclusion")', m['remote_include']))
    if on('include_ext'):
        for f in incs:
            L.append(f'sp.disable_function.function("{f}").value_r("\\\\.(inc|phtml|php)$").allow();')
        for f in incs:
            L.append(_df(f, '.alias("inclusion of a non-PHP file")', m['include_ext']))
    if on('chmod'):
        for v in ('438', '511'):
            L.append(_df('chmod', f'.pos("1").value("{v}").alias("chmod 0{oct(int(v))[2:]}")', m['chmod']))
    if on('env'):
        L.append(_df('putenv', '.pos("0").value_r("^(LD_|GCONV_|PATH=)").alias("environment hijack")', m['env']))
    if on('extract'):
        L.append(_df('extract', '.pos("0").value_r("^_").alias("extract() of request data")', m['extract']))
    if on('ini_basedir'):
        L.append(_df('ini_set', '.pos("0").value_r("open_basedir").alias("open_basedir change")', m['ini_basedir']))
    if on('recon'):
        for f in ('function_exists', 'is_callable'):
            L.append(_df(f, '.pos("0").value_r("^(exec|system|shell_exec|passthru|proc_open|popen|eval)$").alias("backdoor reconnaissance")',
                         m['recon']))
    if on('curl_tls'):
        L.append('sp.disable_function.function("curl_setopt").pos("2").value("1").allow();')
        L.append('sp.disable_function.function("curl_setopt").pos("2").value("2").allow();')
        L.append(_df('curl_setopt', '.pos("1").value("64").alias("SSL_VERIFYPEER turned off")', m['curl_tls']))
        L.append(_df('curl_setopt', '.pos("1").value("81").alias("SSL_VERIFYHOST turned off")', m['curl_tls']))
        L.append(_df('curl_init', '.pos("0").value_r("^file://").alias("file:// in cURL")', m['curl_tls']))
    if on('mail_params'):
        L.append(_df('mail', '.pos("4").value_r("^-").alias("sendmail argument injection")', m['mail_params']))
    return '\n'.join(L) + '\n'


# [snuffleupagus][ip][feature][action] msg in /path/file.php on line N
LOG_RE = re.compile(r'\[snuffleupagus\]\[([^\]]*)\]\[([^\]]*)\]\[([^\]]*)\]\s*(.*?)(?: in (/.*?) on line (\d+))?$')


def parse_line(line):
    m = LOG_RE.search(line)
    if not m:
        return None
    ip, feature, action, msg, path, lineno = m.groups()
    fn = re.search(r"function '([^']+)'", msg) or re.search(r"call to '([^']+)'", msg)
    rule = re.search(r"rule '([^']+)'", msg)
    labels = {'readonly_exec': 'writable PHP file executed', 'eval': 'shell function called from eval()',
              'xxe': 'XML external entity'}
    return {'ip': ip, 'feature': feature, 'action': action, 'msg': msg[:400], 'file': path or '',
            'line': int(lineno) if lineno else 0, 'function': fn.group(1) if fn else '',
            'rule': rule.group(1) if rule else labels.get(feature.lower(), feature)}
