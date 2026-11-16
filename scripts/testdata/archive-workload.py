"""Keep real private writers alive so archive acceptance tests stopped recovery.

Codex's offline thread operations exercise its own persistence without a model
call; SQLite and DinD writers cover descendants that outlive the main workload.
"""

import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tarfile
import time


def codex_state(home):
    # Use only this disposable session's private state, never host credentials.
    state = home / '.codex'
    state.mkdir(exist_ok=True)
    with (home / 'codex-stderr').open('w') as log:
        server = subprocess.Popen(['codex', 'app-server'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=log,
                                  env=dict(os.environ, CODEX_HOME=str(state)))
        try:
            request_id = 0
            buffer = b''

            def rpc(method, params):
                nonlocal request_id, buffer
                request_id += 1
                server.stdin.write((json.dumps(dict(id=request_id, method=method, params=params)) + '\n').encode())
                server.stdin.flush()
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if b'\n' not in buffer:
                        if not select.select([server.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
                            break
                        chunk = os.read(server.stdout.fileno(), 65536)
                        assert chunk, 'Codex exited: ' + (home / 'codex-stderr').read_text()
                        buffer += chunk
                        continue
                    line, buffer = buffer.split(b'\n', 1)
                    message = json.loads(line)
                    if message.get('id') == request_id:
                        assert 'error' not in message, message
                        return message['result']
                raise AssertionError('Codex offline request timed out: ' + method)

            rpc('initialize', {'clientInfo': {'name': 'membrane_archive_test', 'version': '1'}})
            server.stdin.write(b'{"method":"initialized"}\n')
            server.stdin.flush()
            thread = rpc('thread/start', {'cwd': str(home), 'approvalPolicy': 'never',
                                          'sandbox': 'read-only'})['thread']
            thread_id = thread['id']
            rpc('thread/name/set', {'threadId': thread_id, 'name': 'membrane offline archive fixture'})
            rpc('thread/archive', {'threadId': thread_id})
            rpc('thread/unarchive', {'threadId': thread_id})
            rpc('thread/resume', {'threadId': thread_id})
            assert rpc('thread/read', {'threadId': thread_id})['thread']['id'] == thread_id
            rpc('thread/archive', {'threadId': thread_id})
        finally:
            server.terminate()
            server.wait(timeout=10)
    histories = list((state / 'archived_sessions').glob('*' + thread_id + '*'))
    assert len(histories) == 1, histories
    history = histories[0]
    assert thread_id in history.read_text()
    (home / 'codex-report.json').write_text(json.dumps({
        'thread': thread_id, 'history': str(history.relative_to(home)),
        'sha256': hashlib.sha256(history.read_bytes()).hexdigest(),
        'version': subprocess.check_output(['codex', '--version'], text=True).strip(),
    }))


def main():
    mode = sys.argv[1]
    home = Path.home()
    if mode == 'codex-only':
        codex_state(home)
        return
    tool = home / 'tool dir'
    tool.mkdir()
    literal = tool / 'literal [*] file'
    literal.write_text('private selected bytes')
    literal.chmod(0o750)
    (home / 'unselected').write_text('private outside narrow selection')
    subprocess.run(['sudo', 'sh', '-c', 'printf "selected outside home" > /opt/archive-file'], check=True)
    (home / 'host-link').symlink_to(str(Path.cwd()))
    (home / 'private-link').symlink_to(tool)
    os.mkfifo(tool / 'fifo')
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(tool / 'socket'))

    # The alias is created by workload code, absent from Docker's Mounts list.
    # A root read still must fail, and raw export must never contain its marker.
    alias = home / 'workload-alias'
    alias.mkdir()
    subprocess.run(['sudo', 'mount', '--bind', str(Path.cwd()), str(alias)], check=True)
    denied = subprocess.run(['sudo', 'cat', str(alias / 'sealed-marker')], capture_output=True)
    assert denied.returncode != 0 and b'Permission denied' in denied.stderr, denied
    try:
        (alias / 'sealed-marker').read_bytes()
    except OSError as error:
        assert error.errno == errno.EACCES, error
    else:
        raise AssertionError('sealed marker readable through alias')

    writer = """import sqlite3, time
from pathlib import Path
db = sqlite3.connect('live.sqlite')
db.execute('pragma journal_mode=wal')
db.execute('pragma wal_autocheckpoint=0')
db.execute('create table state (id integer primary key, value integer)')
db.execute('insert into state values (1, 0)')
db.commit()
Path('writer-ready').touch()
while True:
    db.execute('update state set value = value + 1 where id = 1')
    db.commit()
    time.sleep(.02)
"""
    with (home / 'writer-log').open('w') as log:
        subprocess.Popen(['python3', '-c', writer], cwd=tool, start_new_session=True,
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    deadline = time.monotonic() + 30
    while not (tool / 'writer-ready').exists():
        assert time.monotonic() < deadline, 'SQLite writer did not start'
        time.sleep(.02)

    if mode == 'full':
        codex_state(home)
        deadline = time.monotonic() + 30
        while subprocess.run(['docker', 'info'], capture_output=True).returncode:
            assert time.monotonic() < deadline, 'DinD did not start'
            time.sleep(.1)
        # Import a small real image without a registry, leaving its storage and
        # an active writer present when the enclosing session shuts down.
        importer = subprocess.Popen(['docker', 'import', '-', 'membrane-archive-writer'], stdin=subprocess.PIPE)
        with tarfile.open(fileobj=importer.stdin, mode='w|') as archive:
            archive.add('trace-workload', arcname='probe')
        importer.stdin.close()
        assert importer.wait() == 0
        subprocess.run(['docker', 'run', '-d', '--name', 'archive-writer',
                        '-v', str(tool) + ':/state', 'membrane-archive-writer',
                        '/probe', 'archive-writer', '/state/dind-writer'], check=True)
        while not (tool / 'dind-writer').exists():
            assert time.monotonic() < deadline, 'DinD writer did not start'
            time.sleep(.02)
        (Path.cwd() / 'dind-id').write_text(subprocess.check_output(
            ['docker', 'inspect', '-f', '{{.State.Pid}}', 'archive-writer'], text=True))

    Path('ready').touch()
    while not Path('continue').exists():
        time.sleep(.02)
    # Leave both child writers running; shutdown, not this script, drains them.
    sys.exit(int(sys.argv[2]))


if __name__ == '__main__':
    main()
