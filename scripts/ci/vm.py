#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Supervise disposable guests; all deadlines and serial logs live outside them."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time

# Use the same kernel diagnostic policy for both kinds of test.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'kunit'))
from run import kernel_diagnostics  # noqa: E402


class VMError(Exception):
    pass


def resolve_ginkgo_label(label):
    path = Path(__file__).resolve().parents[2] / 'tests/ginkgo/internal/testrun/labels.json'
    sets = json.loads(path.read_text())
    expression = sets.get(label.strip(), label)
    if label.strip() in sets and (not isinstance(expression, str) or not expression.strip()):
        raise VMError(f'Ginkgo label set {label!r} must be a nonempty expression')
    return expression


def stop(process):
    """Kill only our own QEMU process group, including on interruption."""
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait(timeout=5)
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def wait_guest(target, peer, deadline, ready, release, started=None, boot_deadline=None):
    while target.poll() is None:
        if peer is not None:
            if peer.poll() is not None:
                raise VMError('initiator exited before the target completed')
            if ready.exists() and not release.exists():
                release.touch()
        if time.monotonic() >= deadline:
            raise VMError('guest deadline expired')
        if (boot_deadline is not None and time.monotonic() >= boot_deadline
                and (not started.exists() or peer is not None and not ready.exists())):
            raise VMError('guest did not become ready before the boot deadline')
        time.sleep(.1)
    if target.returncode != 0:
        raise VMError(f'QEMU exited with {target.returncode}')


def validate_completion(directory, mode, token, manifest, ginkgo_label='', local_only=False):
    try:
        result = json.loads((directory / 'completion.json').read_text())
    except (OSError, ValueError) as exc:
        raise VMError('missing or invalid guest completion report') from exc
    expected = dict(manifest, mode=mode, token=token, exit_code=0,
                    running_kernel=manifest['kernel'])
    if result != expected:
        raise VMError(f'guest failed or completion identity differs: {result}')
    if mode == 'kunit':
        paths = list((directory / 'kunit').glob('*/result.json'))
        if len(paths) != 1:
            raise VMError('expected exactly one KUnit result')
        report = json.loads(paths[0].read_text())
        if (report['status'] != 'PASS' or report['counts']['passed'] == 0
                or report['not_run_suites'] or report['module_state'] != 'unloaded'):
            raise VMError('KUnit did not complete successfully')
    elif mode == 'ginkgo':
        paths = list((directory / 'ginkgo').glob('*/report.json'))
        if local_only:
            if len(paths) != 1:
                raise VMError('expected a report from the local suite only')
        elif len(paths) != 2:
            raise VMError('expected reports from both local and iSCSI suites')
        for path in paths:
            reports = json.loads(path.read_text())
            if (len(reports) != 1 or not reports[0]['SuiteSucceeded']
                    or reports[0]['PreRunStats']['SpecsThatWillRun'] <= 0
                    or not any(spec['LeafNodeType'] == 'It' and spec['State'] == 'passed'
                               for spec in reports[0]['SpecReports'])):
                raise VMError(f'incomplete or failed Ginkgo suite: {path}')
            if reports[0]['SuiteConfig']['LabelFilter'] != ginkgo_label:
                raise VMError(f'Ginkgo label filter differs from the requested selection: {path}')
            # Each run directory is random; the suite label names the transport.
            if local_only and reports[0].get('SuiteLabels') != ['local']:
                raise VMError(f'expected a report from the local suite only: {path}')


def diagnostics(output):
    # Serial logs cannot be overwritten by a guest. dmesg covers console loss
    # on normal completion, but is intentionally not required after a crash.
    paths = list(output.glob('*.serial.log')) + list(output.glob('*/dmesg.log'))
    found = []
    for path in paths:
        lines = path.read_text(errors='replace').splitlines()
        if path.name.endswith('.serial.log'):
            # journal+console prefixes userspace output with process[pid]. A
            # daemon's WARNING is not a kernel diagnostic. Completed guests
            # additionally supply a LOG_KERN-only dmesg capture.
            lines = [line for line in lines if not re.match(
                r'^\[\s*\d+\.\d+\]\s+[^\s\[]+\[\d+\]:', line)]
        events = kernel_diagnostics(lines)
        if events:
            found.append({'file': path.name, 'events': events})
    return found


def print_log(path, tail=False):
    try:
        with path.open('rb') as source:
            if tail:
                source.seek(0, os.SEEK_END)
                source.seek(max(0, source.tell() - 65536))
            text = source.read().decode('utf-8', errors='replace')
    except OSError as exc:
        print(f'Unable to read {path.name}: {exc}')
        return
    lines = text.splitlines()
    if tail:
        lines = lines[-80:]
    # Distinguish guest output from the supervisor's messages.
    for line in lines:
        print('  ' + line)


def print_results(output, result):
    """Replay native test output without changing the supervisor's verdict."""
    mode = result['mode']
    if mode in ('kunit', 'ginkgo'):
        print(f'\n=== {mode} test output ===')
        if mode == 'ginkgo':
            print(f"Label filter: {result['ginkgo_label'] or '<all>'}")
        path = output / 'target/tests.log'
        if path.is_file():
            print_log(path)
        else:
            print('No guest test output was saved.')
    if result['error']:
        print(f"\nError: {result['error']}")
    for item in result['diagnostics']:
        print(f"\n=== Kernel diagnostics: {item['file']} ===")
        for event in item['events']:
            for line in event.splitlines():
                print('  ' + line)
    if result['status'] != 'PASS':
        for path in sorted(output.glob('*.serial.log')):
            print(f'\n=== {path.name}: last 80 lines (up to 64 KiB) ===')
            print_log(path, tail=True)
    print(f"\n{mode}: {result['status']} ({result['elapsed_seconds']}s); {output}", flush=True)


def launch(stack, image, work, output, role, mode, token, accel, network=None, ginkgo_label='',
           local_only=False):
    config, reports = work / role, output / role
    config.mkdir()
    reports.mkdir()
    (config / 'mode').write_text(mode)
    (config / 'token').write_text(token)
    if mode == 'ginkgo':
        (config / 'ginkgo-label').write_text(ginkgo_label)
    if local_only:
        (config / 'local-only').touch()
    overlay = work / f'{role}.qcow2'
    subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'raw',
                    '-b', str(image / 'rootfs.img'), str(overlay)], check=True)
    serial = stack.enter_context((output / f'{role}.serial.log').open('wb'))
    command = [
        'qemu-system-x86_64', '-machine', 'accel=' + ('kvm:tcg' if accel == 'auto' else accel),
        '-m', '1024' if role == 'initiator' else '2048',
        '-cpu', 'host' if accel == 'kvm' else 'max',
        '-smp', '1' if role == 'initiator' else '2', '-display', 'none', '-monitor', 'none',
        '-serial', 'stdio', '-no-reboot', '-nic', 'none',
        '-kernel', str(image / 'vmlinuz'), '-initrd', str(image / 'initramfs'),
        '-append', 'root=/dev/disk/by-id/virtio-scst-ci-root rw console=ttyS0,115200 earlyprintk=serial '
                   'systemd.unit=scst-ci.target net.ifnames=0 biosdevname=0 selinux=0 '
                   'panic=1 oops=panic kunit.enable=1 kunit.autorun=0',
        '-drive', f'file={overlay},format=qcow2,if=none,id=root',
        '-device', 'virtio-blk-pci,drive=root,serial=scst-ci-root',
        '-fsdev', f'local,id=input,path={config},security_model=none,readonly=on',
        '-device', 'virtio-9p-pci,fsdev=input,mount_tag=ci-input',
        # Preserve guest ownership for scstadmin's secure config-file checks
        # while QEMU itself runs as an unprivileged host user.
        '-fsdev', f'local,id=reports,path={reports},security_model=mapped-xattr',
        '-device', 'virtio-9p-pci,fsdev=reports,mount_tag=ci-reports',
    ]
    if mode == 'ginkgo':
        disk = work / 'data.raw'
        with disk.open('wb') as file:
            file.truncate(1024 ** 3)
        command += ['-drive', f'file={disk},format=raw,if=none,id=data',
                    '-device', 'virtio-blk-pci,drive=data,serial=scst-ci-data,'
                               'logical_block_size=4096,physical_block_size=4096']
    if network:
        server = 'on' if role == 'target' else 'off'
        command += ['-netdev', f'stream,id=peer,server={server},addr.type=unix,addr.path={network}',
                    '-device', 'virtio-net-pci,netdev=peer,mac=52:54:00:12:34:'
                    + ('01' if role == 'target' else '02')]
    (output / f'{role}.command.json').write_text(json.dumps(command, indent=2) + '\n')
    process = subprocess.Popen(command, stdout=serial, stderr=subprocess.STDOUT,
                               start_new_session=True)
    stack.callback(stop, process)
    return process


def configure_ssh(work):
    # Generated per run, used only on the private guest-to-guest network and
    # removed with work. Private keys are never uploaded as artifacts.
    for name in ('id_ed25519', 'ssh_host_key'):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-f', str(work / name)], check=True)
    target, peer = work / 'target', work / 'initiator'
    (target / 'id_ed25519').write_bytes((work / 'id_ed25519').read_bytes())
    (target / 'known_hosts').write_text('192.0.2.2 ' + (work / 'ssh_host_key.pub').read_text())
    (peer / 'ssh_host_key').write_bytes((work / 'ssh_host_key').read_bytes())
    (peer / 'authorized_keys').write_bytes((work / 'id_ed25519.pub').read_bytes())
    (target / 'ssh-ready').touch()
    (peer / 'ssh-ready').touch()


def run(image, output, mode, timeout, accel, ginkgo_label='', local_only=False):
    manifest = json.loads((image / 'image.json').read_text())
    if mode in ('kunit', 'ginkgo') and manifest['suite'] != mode:
        raise VMError('image was built for a different test suite')
    if mode == 'ginkgo':
        ginkgo_label = resolve_ginkgo_label(ginkgo_label)
        if local_only:
            # Group the resolved expression so OR terms cannot select iSCSI.
            ginkgo_label = f'local && ({ginkgo_label})' if ginkgo_label.strip() else 'local'
    output.mkdir(parents=True, exist_ok=False)
    token = secrets.token_hex(16)
    result = dict(mode=mode, image=manifest, status='ERROR', error=None)
    if mode == 'ginkgo':
        result['ginkgo_label'] = ginkgo_label
        result['local_only'] = local_only
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='scst-ci-') as temporary, ExitStack() as stack:
            work = Path(temporary)
            # Local-only runs need no iSCSI initiator, so no second guest or network.
            network = work / 'network.sock' if mode == 'ginkgo' and not local_only else None
            target = launch(stack, image, work, output, 'target', mode, token, accel, network,
                            ginkgo_label, local_only)
            peer = None
            if network:
                # The listening QEMU must create its socket before its peer connects.
                while not network.exists():
                    if target.poll() is not None or time.monotonic() - started > 10:
                        raise VMError('target did not create the private network')
                    time.sleep(.05)
                peer = launch(stack, image, work, output, 'initiator', 'initiator', token, accel, network)
                configure_ssh(work)
            wait_guest(target, peer, started + timeout, output / 'initiator/ready',
                       work / 'target/peer-ready', output / 'target/started', started + 240)
            validate_completion(output / 'target', mode, token, manifest, ginkgo_label,
                                local_only)
        result['status'] = 'PASS'
    except (VMError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    finally:
        result['diagnostics'] = diagnostics(output)
        if result['diagnostics']:
            result['status'] = 'ERROR'
            result['error'] = result['error'] or 'kernel diagnostics in guest logs'
        result['elapsed_seconds'] = round(time.monotonic() - started, 2)
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print_results(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('kunit', 'ginkgo', 'self-test'))
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--timeout', type=int, default=10000)
    parser.add_argument('--accel', choices=('auto', 'tcg', 'kvm'), default='auto')
    parser.add_argument('--ginkgo-label', default='',
                        help='Ginkgo label set or expression (default: all tests)')
    parser.add_argument('--local-only', action='store_true',
                        help='run only local Ginkgo specs, without an iSCSI initiator guest')
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    if args.ginkgo_label and args.mode != 'ginkgo':
        parser.error('--ginkgo-label requires ginkgo mode')
    if args.local_only and args.mode != 'ginkgo':
        parser.error('--local-only requires ginkgo mode')
    image, output = args.image.resolve(), args.output.resolve()
    # QEMU's key-value arguments cannot represent arbitrary comma-containing paths.
    if any(',' in str(path) for path in (image, output, Path(tempfile.gettempdir()))):
        parser.error('image, output and temporary paths must not contain commas')
    subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=image, check=True)
    if args.mode == 'self-test':
        smoke = run(image, output / 'smoke', 'smoke', args.timeout, args.accel)
        if smoke['status'] != 'PASS':
            return 1
        panic = run(image, output / 'panic', 'panic', args.timeout, args.accel)
        hang = run(image, output / 'hang', 'hang', args.timeout, args.accel)
        # Expected failure must be the injected fault, never an arbitrary boot error.
        return int(not (panic['status'] == 'ERROR'
                       and any('Kernel panic' in event for item in panic['diagnostics'] for event in item['events'])
                       and hang['error'] == 'guest deadline expired'
                       and (output / 'hang/target/started').is_file()
                       and (output / 'hang/target/started').read_text().strip() == 'hang'))
    return int(run(image, output, args.mode, args.timeout, args.accel,
                   args.ginkgo_label, args.local_only)['status'] != 'PASS')


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
