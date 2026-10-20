import json
from pathlib import Path
import ssl
import sys
from urllib.request import urlopen

config = json.loads(Path(sys.argv[1]).read_text())
context = ssl.create_default_context(cafile=config['tlsCert'])
with urlopen(config['origin']+'/health/ready', context=context, timeout=3) as response:
    if response.status != 200 or json.load(response) != {'status': 'READY'}: raise SystemExit(1)
