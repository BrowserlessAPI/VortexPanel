"""AI review of each new upstream release, before anything is built.

For every planned version the agent reads the upstream changelog and answers:
  security  - does this release fix a security problem (CVE, advisory)?
  breaking  - anything that can break a VortexPanel server on update
              (removed directives/options, changed defaults, config format, data upgrade)
  hold      - true only for a breaking change that needs a person
  notes     - the short release note users see in the panel (plain text, no emojis)

Provider (repository secrets / variables), first one set wins:
  CLAUDE_CODE_OAUTH_TOKEN  your Claude subscription (Pro, Max, Team, Enterprise): the workflow
                           runs the Claude Code GitHub Action as the review agent, no API billing
  ANTHROPIC_API_KEY (+ AI_MODEL, default claude-sonnet-5-5)             Claude API
  AI_BASE_URL + AI_API_KEY + AI_MODEL                                     any OpenAI-compatible API
None configured: the release still goes ahead, with notes taken from the changelog.

    python3 ai_review.py plan.json             -> review.json, notes/<app>-<version>.md (API / changelog)
    python3 ai_review.py plan.json --prepare   -> review-input/ tasks for the subscription agent
    python3 ai_review.py plan.json --collect   -> review.json from the agent's review-output/
"""
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

PROMPT = """You review a new upstream release of server software for VortexPanel, a Linux hosting
control panel that installs and updates this software on customer servers automatically.

Software: {name}
New version: {version} (track {track})
Previous published version on this track: {prev}

Changelog / release notes (may be long, may cover several versions):
---
{changelog}
---

Answer with ONLY a JSON object, no prose around it:
{{
 "security": true|false,          // fixes a vulnerability (CVE, security advisory)
 "cves": ["CVE-..."],
 "breaking": ["..."],             // changes that can break an existing server on update; empty if none
 "hold": true|false,              // true ONLY if a breaking change needs a human before rollout
 "notes": "..."                   // 2-5 short plain sentences for server admins; no emojis, no markdown headers
}}"""


def changelog_for(recipe, item):
    cl = recipe.get('changelog')
    if item.get('notes_text'):
        return item['notes_text']
    if not cl:
        return ''
    url = cl.format(version=item['version'], track=item['track'], tag=item.get('tag', ''),
                    major=item['version'].split('.')[0], under=item['version'].replace('.', '_'))
    try:
        text = C.http_get(url, timeout=30)
    except Exception as e:  # noqa: BLE001
        C.log(f'changelog {url}: {e}')
        return ''
    text = re.sub(r'<script.*?</script>|<style.*?</style>', ' ', text, flags=re.S | re.I)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'[ \t]+', ' ', text)
    # keep the part about this version when the page covers many
    i = text.find(item['version'])
    return text[max(0, i - 200): i + 12000] if i >= 0 else text[:12000]


def _call(prompt):
    if os.environ.get('ANTHROPIC_API_KEY'):
        body = {'model': os.environ.get('AI_MODEL') or 'claude-sonnet-5-5', 'max_tokens': 900,
                'messages': [{'role': 'user', 'content': prompt}]}
        req = urllib.request.Request('https://api.anthropic.com/v1/messages', data=json.dumps(body).encode(),
                                     headers={'x-api-key': os.environ['ANTHROPIC_API_KEY'],
                                              'anthropic-version': '2023-06-01', 'content-type': 'application/json'})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())['content'][0]['text']
    if os.environ.get('AI_BASE_URL') and os.environ.get('AI_API_KEY'):
        body = {'model': os.environ.get('AI_MODEL', ''), 'max_tokens': 900, 'temperature': 0,
                'messages': [{'role': 'user', 'content': prompt}]}
        req = urllib.request.Request(os.environ['AI_BASE_URL'].rstrip('/') + '/chat/completions',
                                     data=json.dumps(body).encode(),
                                     headers={'Authorization': 'Bearer ' + os.environ['AI_API_KEY'],
                                              'content-type': 'application/json'})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())['choices'][0]['message']['content']
    return None


def _parse(text):
    m = re.search(r'\{.*\}', text or '', re.S)
    if not m:
        return None
    try:
        d = json.loads(re.sub(r'//[^\n]*', '', m.group(0)))
    except ValueError:
        return None
    notes = re.sub(r'[^\x09\x0a\x20-\x7e -ɏ]', '', str(d.get('notes') or ''))[:1200]
    return {'security': bool(d.get('security')), 'cves': [c for c in d.get('cves') or [] if re.fullmatch(r'CVE-\d{4}-\d{4,7}', str(c))][:30],
            'breaking': [str(b)[:300] for b in (d.get('breaking') or [])][:10], 'hold': bool(d.get('hold')),
            'notes': notes, 'by': 'ai'}


def fallback(changelog, item):
    cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', changelog)))[:30]
    # security only with evidence: CVE ids, or the upstream source marks it (Node.js)
    sec = bool(cves) or bool(item.get('security'))
    first = ' '.join(changelog.split())[:400]
    return {'security': sec, 'cves': cves, 'breaking': [], 'hold': False,
            'notes': f"Upstream release {item['version']}." + (' Includes security fixes.' if sec else '')
                     + (f' {first}' if first and len(first) > 40 else ''), 'by': 'changelog'}


def review(item, recipe, catalog):
    prev = max((r['version'] for r in C.releases(catalog, item['app']) if r.get('track') == item['track']),
               key=C.vt, default='none')
    text = changelog_for(recipe, item)
    try:
        out = _parse(_call(PROMPT.format(name=recipe.get('name', item['app']), version=item['version'],
                                         track=item['track'], prev=prev, changelog=text[:14000] or '(not available)')))
    except Exception as e:  # noqa: BLE001
        C.log(f'AI review failed for {item["app"]} {item["version"]}: {e}')
        out = None
    return out or fallback(text, item)


def write_outputs(pl, res):
    os.makedirs('notes', exist_ok=True)
    for key, rv in res.items():
        with open(f'notes/{key}.md', 'w') as f:
            f.write(rv['notes'] + '\n')
            if rv['cves']:
                f.write('\nSecurity fixes: ' + ', '.join(rv['cves']) + '\n')
            if rv['breaking']:
                f.write('\nChanges to check after updating:\n' + ''.join(f'- {b}\n' for b in rv['breaking']))
        C.log(f"{key}: security={rv['security']} hold={rv['hold']} by={rv['by']}")
    json.dump(res, open('review.json', 'w'), indent=1)
    C.gh_output('held', ','.join(k for k, v in res.items() if v['hold']))


def _prev(item, catalog):
    return max((r['version'] for r in C.releases(catalog, item['app']) if r.get('track') == item['track']),
               key=C.vt, default='none')


AGENT_IN, AGENT_OUT = 'review-input', 'review-output'


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    pl = json.load(open(args[0] if args else 'plan.json'))
    rs = C.recipes()
    try:
        cat = C.load_catalog()
    except Exception:  # noqa: BLE001
        cat = C.empty_catalog()

    if '--prepare' in sys.argv:
        # Claude subscription agent (Claude Code GitHub Action): one task file per release;
        # the agent writes its JSON answer to review-output/<key>.json
        os.makedirs(AGENT_IN, exist_ok=True)
        os.makedirs(AGENT_OUT, exist_ok=True)
        for item in pl:
            key = f"{item['app']}-{item['version']}"
            r = rs[item['app']]
            text = changelog_for(r, item)
            with open(os.path.join(AGENT_IN, f'{key}.md'), 'w') as f:
                f.write(PROMPT.format(name=r.get('name', item['app']), version=item['version'], track=item['track'],
                                      prev=_prev(item, cat), changelog=text[:14000] or '(not available)'))
                f.write(f'\n\nWrite ONLY that JSON object to the file {AGENT_OUT}/{key}.json\n')
            with open(os.path.join(AGENT_IN, f'{key}.changelog'), 'w') as f:
                f.write(text)
        C.log(f'{len(pl)} review task(s) written to {AGENT_IN}/')
        return

    res = {}
    for item in pl:
        key = f"{item['app']}-{item['version']}"
        rv = None
        if '--collect' in sys.argv:
            try:
                rv = _parse(open(os.path.join(AGENT_OUT, f'{key}.json')).read())
                if rv:
                    rv['by'] = 'claude-agent'
            except OSError:
                rv = None
            if rv is None:
                C.log(f'{key}: no usable answer from the agent; using the changelog')
                try:
                    text = open(os.path.join(AGENT_IN, f'{key}.changelog')).read()
                except OSError:
                    text = ''
                rv = fallback(text, item)
        else:
            rv = review(item, rs[item['app']], cat)
        res[key] = rv
    write_outputs(pl, res)


if __name__ == '__main__':
    main()
