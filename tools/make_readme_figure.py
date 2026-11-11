"""Generate the README benchmark scorecard from the released episode metadata."""
import json
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]


def main():
    rows = json.loads((ROOT / 'evidence/final.json').read_text(encoding='utf8'))['rows']
    scores = []
    for arm in ('rules', 'v0'):
        normal = [r for r in rows if r['mode'] == 'clean' and r['arm'] == arm]
        scores.append((sum(r['official_utility'] is True for r in normal), len(normal)))
    baseline, candidate = scores
    gain = candidate[0] - baseline[0]
    delta = candidate[0] / candidate[1] * 100 - baseline[0] / baseline[1] * 100
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="650" viewBox="0 0 1200 650" role="img" aria-labelledby="title desc">',
             '<title id="title">Control Layer V0 benchmark: 44 to 47 completed tasks out of 97</title>',
             '<desc id="desc">Official AgentDojo SDK task success improves from 45.4 to 48.5 percent. Three semantic gains and zero losses. Official attack successes remain 0 versus 1; audited unauthorized writes are zero for both arms. Warm cost increases 2.25 percent. Local development evaluation, not an official leaderboard submission.</desc>',
             '<rect width="1200" height="650" fill="#0b100d" rx="6"/>',
             '<g font-family="Segoe UI,Arial,sans-serif" fill="#edf3ee">']

    def text(x, y, content, size=20, fill='#edf3ee', weight='400'):
        parts.append(f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" font-weight="{weight}">{escape(content)}</text>')

    text(48, 52, 'AgentDojo v1 · Task success rate', 34, weight='600')
    text(48, 85, 'Same Qwen3.5 4B actor · Official SDK scoring · Local development evaluation', 19, '#a9bbaf')
    for i, ((count, total), label) in enumerate(zip(scores, ('R2 rules baseline', 'Control Layer V0'))):
        y = 150 + i * 100
        rate = count / total * 100
        color = '#79edab' if i else '#82988a'
        text(48, y + 6, label, 23, color)
        text(48, y + 34, f'{count} / {total} tasks', 19, '#a9bbaf')
        parts.append(f'<rect x="286" y="{y-17}" width="674" height="39" fill="#1d2a22"/>')
        parts.append(f'<rect x="286" y="{y-17}" width="{674*rate/100:.3f}" height="39" fill="{color}"/>')
        text(1004, y + 15, f'{rate:.1f}%', 40, color)
    parts.append('<path d="M286 305H960" stroke="#526b5a"/>')
    for percent in (0, 25, 50, 75, 100):
        x = 286 + 674 * percent / 100
        parts.append(f'<path d="M{x} 305v5" stroke="#526b5a"/>')
        text(x - 12, 332, str(percent) + '%', 17, '#a9bbaf')
    parts.append('<path d="M48 366H1152M48 474H1152" stroke="#304737"/>')
    for x, value, label in ((48, f'+{gain}', 'semantically completed tasks'),
                            (460, f'+{delta:.2f} pp', 'absolute completion-rate gain'),
                            (884, '0', 'paired semantic losses')):
        text(x, 416, value, 42, '#79edab')
        text(x, 448, label, 19, '#a9bbaf')
    for x, label, value, color in ((48, 'OFFICIAL ATTACK SUCCESSES', '0/54 → 1/54', '#efb785'),
                                  (460, 'AUDITED UNAUTHORIZED WRITES', '0/54 → 0/54', '#edf3ee'),
                                  (884, 'WARM WALL COST', '+2.25%', '#efb785')):
        text(x, 518, label, 17, '#a9bbaf')
        text(x, 560, value, 30, color)
    text(48, 609, 'Reused development benchmark · Exact paired McNemar p = 0.25 · 151 matched episode pairs', 18, '#a9bbaf')
    parts.append('</g></svg>')
    (ROOT / 'assets/readme/benchmark-scorecard.svg').write_text('\n'.join(parts) + '\n', encoding='utf8')


if __name__ == '__main__':
    main()
