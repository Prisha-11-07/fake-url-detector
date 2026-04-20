from pathlib import Path
path = Path('static/style.css')
text = path.read_text()
replacements = {
    'background: rgba(255,255,255,0.06);': 'background: rgba(0, 255, 170, 0.08);',
    'background: rgba(255, 255, 255, 0.04);': 'background: rgba(0, 255, 170, 0.06);',
    'background: rgba(255, 255, 255, 0.05);': 'background: rgba(0, 255, 170, 0.06);',
    'background: rgba(255, 255, 255, 0.1);': 'background: rgba(0, 255, 170, 0.08);',
    'border: 1px solid rgba(255, 255, 255, 0.1);': 'border: 1px solid rgba(0, 255, 170, 0.15);',
    'border-bottom: 1px solid rgba(255, 255, 255, 0.1);': 'border-bottom: 1px solid rgba(0, 255, 170, 0.12);',
    'border-top: 1px solid rgba(255, 255, 255, 0.1);': 'border-top: 1px solid rgba(0, 255, 170, 0.12);',
    'border: 1px solid rgba(255, 255, 255, 0.2);': 'border: 1px solid rgba(0, 255, 170, 0.2);',
}
for old, new in replacements.items():
    text = text.replace(old, new)
path.write_text(text)
print('Updated white translucent backgrounds and borders')
