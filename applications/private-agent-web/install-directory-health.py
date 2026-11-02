#!/usr/bin/env python3
"""Install five-minute directory checks in the current user's crontab."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess

APP = Path(__file__).resolve().parent
deno = shutil.which('deno')
if not deno:
    raise SystemExit('deno must be installed on the monitoring host')
if not (Path.home()/'.hermes-3090/.env').is_file():
    raise SystemExit('existing on-host Hermes environment is required')
state = Path.home()/'.local/state/dsmack-directory'
state.mkdir(parents=True, exist_ok=True, mode=0o700)
notifier = APP/'directory-notify.sh'
notifier.chmod(0o755)
subprocess.run([deno, 'cache', str(APP/'directory-health.mjs')], check=True)
prior = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
if prior.returncode and not (prior.returncode == 1 and 'no crontab for' in prior.stderr):
    raise SystemExit('could not read existing crontab: '+prior.stderr)
lines = [line for line in prior.stdout.splitlines() if not line.endswith('# dsmack-directory')]
for target, project in [('production', 'private-agent'), ('staging', 'private-agent-staging')]:
    command = [deno, 'run', '--allow-net', '--allow-read', '--allow-write', '--allow-run',
               str(APP/'directory-health.mjs'), target,
               f'https://pod.dstack.soc1024.com/{project}/config.json',
               str(state/(target+'.json')), str(notifier)]
    shell = ' '.join(shlex.quote(part) for part in command)
    locked = 'flock -n '+shlex.quote(str(state/(target+'.lock')))+' '+shell
    lines.append('*/5 * * * * '+locked+' >>'+shlex.quote(str(state/(target+'.log')))+' 2>&1 # dsmack-directory')
subprocess.run(['crontab', '-'], input='\n'.join(lines)+'\n', text=True, check=True)
print('Installed five-minute production and staging directory checks; state and logs: '+str(state))
