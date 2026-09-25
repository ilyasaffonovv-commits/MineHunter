"""Generates docs/RULES.md (the rule catalogue) from the C# sources and rules/core.json. Run from anywhere:  python gen_rules_doc.py"""
import re, glob, json, collections, os

root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
src = os.path.join(root, 'src', 'MineHunter')

STR = r'"((?:[^"\\]|\\.)*)"'
rules = {}
for f in glob.glob(os.path.join(src, '**', '*.cs'), recursive=True):
    s = open(f, encoding='utf-8').read()
    pat = r'new Evidence\(\s*"([A-Za-z0-9_.]+)"\s*,\s*(?:EvidenceCategory\.(\w+)|FileIntel\.ParseCat\([^)]*\)|(\w+))\s*,\s*(-?\d+)\s*,\s*' + STR
    for m in re.finditer(pat, s):
        rid, cat, other, w, text = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        rules.setdefault(rid, {'cat': cat or other or '?', 'w': set(), 'en': text})['w'].add(int(w))

# second pass: rules whose text is built dynamically (string concatenation) - keep id, category and weight
for f in glob.glob(os.path.join(src, '**', '*.cs'), recursive=True):
    s = open(f, encoding='utf-8').read()
    pat = r'new Evidence\(\s*"([A-Za-z0-9_.]+)"\s*,\s*(?:EvidenceCategory\.(\w+)|FileIntel\.ParseCat\([^)]*\)|(\w+))\s*,\s*(-?\d+)'
    for m in re.finditer(pat, s):
        rid, cat, other, w = m.group(1), m.group(2), m.group(3), m.group(4)
        rules.setdefault(rid, {'cat': cat or other or '?', 'w': set(), 'en': '(text is built at run time)'})['w'].add(int(w))

loc = open(os.path.join(src, 'Report', 'Loc.cs'), encoding='utf-8').read()
ru = {}
for m in re.finditer(r'\{\s*"([A-Z][A-Z0-9_.]+)"\s*,\s*' + STR + r'\s*\}', loc):
    ru[m.group(1)] = m.group(2).replace('\\"', '"')

core = json.load(open(os.path.join(root, 'rules', 'core.json'), encoding='utf-8'))
out = []
out.append('# Каталог правил (генерируется из исходников)\n')
out.append('Каждая улика это правило с идентификатором, категорией и весом. Как из улик получается вердикт, описано в [RISK_MODEL.md](RISK_MODEL.md). '
           'Отрицательный вес означает доверие (например, подпись известного издателя).\n')
out.append('Правил в коде: %d, правил командной строки в `rules/core.json`: %d, версия пакета правил: `%s`.\n' % (len(rules), len(core.get('cmdlinePatterns', [])), core.get('version')))
bycat = collections.defaultdict(list)
for rid, v in rules.items():
    bycat[v['cat']].append((rid, v))
order = ['Reputation', 'Content', 'Behavior', 'Masquerade', 'Persistence', 'Tamper', 'Network', 'Location', 'Signature', 'Trust']
names = {'Reputation': 'Репутация (известные хеши/семейства)', 'Content': 'Содержимое файла и командной строки', 'Behavior': 'Поведение процессов',
         'Masquerade': 'Маскировка под системные/фирменные программы', 'Persistence': 'Закрепление в системе (автозапуск)', 'Tamper': 'Вмешательство в защиту системы',
         'Network': 'Сеть', 'Location': 'Расположение', 'Signature': 'Цифровая подпись', 'Trust': 'Доверие (снижает риск)'}
for c in order + [k for k in bycat if k not in order]:
    if c not in bycat:
        continue
    out.append('\n## %s\n' % names.get(c, c))
    out.append('| Правило | Вес | Что означает |')
    out.append('|---|---|---|')
    for rid, v in sorted(bycat[c], key=lambda x: (-max(x[1]['w']), x[0])):
        w = '/'.join(str(x) for x in sorted(v['w'], reverse=True))
        out.append('| `%s` | %s | %s |' % (rid, w, (ru.get(rid) or v['en']).replace('|', '\\|')))
out.append('\n## Правила командной строки (`rules/core.json`)\n')
out.append('| Правило | Вес | Определяющее | Категория | Что означает |')
out.append('|---|---|---|---|---|')
for c in core.get('cmdlinePatterns', []):
    out.append('| `%s` | %s | %s | %s | %s |' % (c['id'], c.get('weight'), 'да' if c.get('definitive') else 'нет', c.get('category', 'Content'), (c.get('textRu') or ru.get(c['id']) or c.get('text', '')).replace('|', '\\|')))
out.append('\n## Известные пути (IOC, категория Reputation)\n')
out.append('| Правило | Вес | Что означает |')
out.append('|---|---|---|')
for c in core.get('knownIocPaths', []):
    out.append('| `%s` | %s | %s |' % (c['id'], c.get('weight'), (c.get('textRu') or ru.get(c['id']) or c.get('text', '')).replace('|', '\\|')))
out.append('\nВ пакете: имён файлов известных майнеров %d (`minerFileNames`), доверенных издателей %d, строк-маркеров майнеров %d.' % (len(core.get('minerFileNames', [])), len(core.get('trustedPublishers', [])), sum(len(v) for v in core.get('minerStrings', {}).values())))
dst = os.path.join(root, 'docs', 'RULES.md')
open(dst, 'w', encoding='utf-8').write('\n'.join(out) + '\n')
print('written', dst, sum(len(v) for v in bycat.values()), 'rules')
