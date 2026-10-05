"""Conservative source scan. Prints file/line only, never matching values."""
import re
import subprocess
from pathlib import Path
patterns = [re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'), re.compile(r'AKIA[0-9A-Z]{16}'), re.compile(r'(?i)(?:password|access_token|refresh_token|authorization)\s*[:=]\s*[\"\x27](?!\[REDACTED\]|fixture|test|REPLACE|password|token|Authorization)[^\"\x27\n]{16,}[\"\x27]')]
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],text=True).splitlines()
findings=[]
for filename in paths:
    p=Path(filename)
    if p.name=='scan_secrets.py' or '__pycache__' in p.parts: continue
    try: lines=p.read_text().splitlines()
    except (UnicodeError,OSError): continue
    for number,line in enumerate(lines,1):
        if any(pattern.search(line) for pattern in patterns): findings.append(f'{filename}:{number}')
print('Secret scan: '+('FAIL '+', '.join(findings) if findings else 'PASS (pattern-based; no detected credentials)'))
raise SystemExit(bool(findings))
