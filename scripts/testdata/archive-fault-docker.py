#!/usr/bin/env python3
"""Disposable Docker shim for archive failure acceptance; never used by Membrane.

Synthetic streams make truncation/cancellation deterministic without filling a
disk or restarting the shared daemon. Normal and missing-source exports use the
real backend; group 42 separately proves its mount-exclusion contract.
"""

import json
import os
from pathlib import Path
import sys
import tarfile
import time

args = sys.argv[1:]
gate = Path(os.environ['ARCHIVE_TEST_DIR'])
mode = os.environ.get('ARCHIVE_TEST_MODE', '')
docker = os.environ['ARCHIVE_TEST_DOCKER']
with (gate / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(args) + '\n')
if args[0] == 'start':
    (gate / 'started').touch()
if (mode == 'runtime-error' and args[0] == 'inspect'
        and args[-1].startswith('membrane-agent-') and (gate / 'started').exists()):
    # A failed collection command, not a complete daemon or VM outage.
    sys.exit('injected archive runtime transport failure')

if mode == 'cancel' and args[:2] == ['rm', '-f'] and args[-1].startswith('membrane-agent-'):
    (gate / 'cleanup-started').touch()
    deadline = time.monotonic() + 90
    while not (gate / 'cleanup-release').exists():
        if time.monotonic() > deadline:
            sys.exit('test cleanup gate timed out')
        time.sleep(.02)

if args[0] != 'export':
    os.execv(docker, ['docker', *args])
(gate / 'before-export').touch()
deadline = time.monotonic() + 90
while not (gate / 'export').exists():
    if time.monotonic() > deadline:
        sys.exit('test export gate timed out')
    time.sleep(.02)
if mode not in ('broken', 'cancel'):
    os.execv(docker, ['docker', *args])

# A selected, incompressible member must reach the partial file while the
# producer is still running. With a whole-stream buffer that cannot happen.
header = tarfile.TarInfo('home/agent/private/injected')
header.mode, header.size = 0o600, 1024 * 1024
sys.stdout.buffer.write(header.tobuf())
blocks = 2 if mode == 'broken' else 16
for _ in range(blocks):
    sys.stdout.buffer.write(os.urandom(65536))
sys.stdout.buffer.flush()
if mode == 'cancel':
    # No subprocess here: cancelling Docker must reap the actual producer.
    (gate / 'producer-pid').write_text(str(os.getpid()))
    while time.monotonic() < deadline:
        time.sleep(.02)
    sys.exit('test producer was not cancelled')
sys.exit('injected archive producer failure')
