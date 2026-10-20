/* VortexPanel language packs.
 *
 * The interface is written in English. A language pack is a JSON object
 * mapping English UI strings to translations (web/static/i18n/<code>.json,
 * or /opt/vortexpanel/data/i18n/<code>.json for your own packs, which
 * survive updates). Text nodes, placeholders and titles whose text exactly
 * matches an English string are replaced, also when Alpine changes them
 * later (MutationObserver). Strings without a translation stay English.
 */
(function () {
  var LANG_KEY = 'vp-lang';
  var dict = null;
  var lang = 'en';
  try { lang = localStorage.getItem(LANG_KEY) || 'en'; } catch (e) {}
  var SKIP = {SCRIPT: 1, STYLE: 1, TEXTAREA: 1, PRE: 1, CODE: 1, INPUT: 1, SELECT: 0};

  function t(s) {
    if (!dict || typeof s !== 'string') return s;
    var k = s.trim();
    if (!k) return s;
    var v = dict[k];
    if (v === undefined || v === k) return s;
    // keep the original surrounding whitespace
    var lead = s.match(/^\s*/)[0], trail = s.match(/\s*$/)[0];
    return lead + v + trail;
  }
  window.vpT = t;
  window.vpLang = function () { return lang; };

  function skipNode(el) {
    for (var n = el; n && n.nodeType === 1; n = n.parentNode) {
      if (SKIP[n.tagName] || (n.hasAttribute && (n.hasAttribute('data-no-i18n') || (n.classList && (n.classList.contains('terminal-out') || n.classList.contains('CodeMirror') || n.classList.contains('xterm')))))) return true;
    }
    return false;
  }

  function translateText(node) {
    var v = node.nodeValue;
    if (!v || !/[A-Za-z]/.test(v)) return;
    var nv = t(v);
    if (nv !== v) node.nodeValue = nv;
  }

  function translateAttrs(el) {
    ['placeholder', 'title', 'aria-label'].forEach(function (a) {
      var v = el.getAttribute && el.getAttribute(a);
      if (v && /[A-Za-z]/.test(v)) {
        var nv = t(v);
        if (nv !== v) el.setAttribute(a, nv);
      }
    });
  }

  function walk(root) {
    if (!dict || !root) return;
    if (root.nodeType === 3) { if (!skipNode(root.parentNode)) translateText(root); return; }
    if (root.nodeType !== 1 || skipNode(root)) return;
    translateAttrs(root);
    var w = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        if (n.nodeType === 1) return SKIP[n.tagName] || (n.hasAttribute('data-no-i18n')) ||
          (n.classList && (n.classList.contains('terminal-out') || n.classList.contains('CodeMirror') || n.classList.contains('xterm')))
          ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var n;
    while ((n = w.nextNode())) {
      if (n.nodeType === 3) translateText(n); else translateAttrs(n);
    }
  }

  function observe() {
    var pending = [];
    var scheduled = false;
    var mo = new MutationObserver(function (muts) {
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        if (m.type === 'characterData') pending.push(m.target);
        else if (m.type === 'attributes') pending.push(m.target);
        else for (var j = 0; j < m.addedNodes.length; j++) pending.push(m.addedNodes[j]);
        if (m.type === 'childList' && m.target && m.target.nodeType === 1) pending.push(m.target);
      }
      if (!scheduled) {
        scheduled = true;
        requestAnimationFrame(function () {
          scheduled = false;
          var list = pending; pending = [];
          for (var k = 0; k < list.length; k++) {
            var x = list[k];
            if (x.nodeType === 3) { if (!skipNode(x.parentNode)) translateText(x); }
            else if (x.nodeType === 1 && x.childNodes.length <= 3 && !skipNode(x)) {
              translateAttrs(x);
              for (var c = 0; c < x.childNodes.length; c++) if (x.childNodes[c].nodeType === 3) translateText(x.childNodes[c]);
              if (x.children.length) walk(x);
            } else if (x.nodeType === 1) walk(x);
          }
        });
      }
    });
    mo.observe(document.body, {subtree: true, childList: true, characterData: true,
                               attributes: true, attributeFilter: ['placeholder', 'title', 'aria-label']});
  }

  window.vpSetLanguage = function (code) {
    try { localStorage.setItem(LANG_KEY, code || 'en'); } catch (e) {}
    location.reload();
  };

  window.vpLanguages = function () {
    return fetch('/api/i18n', {cache: 'no-store'}).then(function (r) { return r.json(); })
      .then(function (d) { return d.languages || []; }).catch(function () { return []; });
  };

  if (lang && lang !== 'en') {
    document.documentElement.lang = lang;
    fetch('/api/i18n/' + encodeURIComponent(lang), {cache: 'no-cache'})
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || typeof d !== 'object') return;
        dict = d;
        var start = function () { walk(document.body); observe(); };
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
      }).catch(function () {});
  }
})();
