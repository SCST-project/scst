# SPDX-License-Identifier: GPL-2.0-only
"""Check plain regression builds without downloading or compiling a kernel."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / 'scripts/kernel/run-regression-tests').read_text()
CONFIGURE = re.search(r'^function patch_and_configure_kernel \{\n.*?^\}',
                      SCRIPT, re.M | re.S).group()
COMPILE = re.search(r'^function compile_scst \{\n.*?^\}', SCRIPT, re.M | re.S).group()
PREAMBLE = SCRIPT.split('function usage', 1)[0]
PREAMBLE = re.sub(r'^source .*$', '', PREAMBLE, flags=re.M)


class RegressionConfigTests(unittest.TestCase):
    def configure(self, config, reenable=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kernel = root / 'linux-4.9'
            kernel.mkdir()
            (root / 'input.config').write_text(config)
            (root / 'scst-4.9-kernel-matching-line-numbers.patch').touch()
            # Exercise the production function; only patch/make are inert.
            harness = '''
outputdir=$1
reenable=$2
multiple_patches=false
ipv6=true
kernel_version() { printf '%s\\n' "$1"; }
patch() { cat >/dev/null; }
make() {
    case "$*" in
        '-s allmodconfig') cp "$outputdir/input.config" .config ;;
        '-s oldconfig')
            if [ "$reenable" = y ]; then
                sed -i 's/^CONFIG_KUNIT=.*/CONFIG_KUNIT=y/' .config
            fi ;;
        *) return 1 ;;
    esac
}
'''
            result = subprocess.run(['bash', '-c', harness + CONFIGURE +
                                     '\npatch_and_configure_kernel 4.9\n',
                                     'test-regression', str(root), 'y' if reenable else 'n'],
                                    capture_output=True, text=True)
            return result, (kernel / '.config').read_text()

    def test_plain_build_without_unwinder_or_kunit_option(self):
        result, _ = self.configure('CONFIG_FRAME_POINTER=y\n')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_allmodconfig_kunit_is_disabled(self):
        for mode in ('y', 'm'):
            with self.subTest(mode=mode):
                result, config = self.configure('CONFIG_UNWINDER_FRAME_POINTER=n\n'
                                                f'CONFIG_KUNIT={mode}\n')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('CONFIG_KUNIT=n\n', config)
                self.assertIn('CONFIG_UNWINDER_FRAME_POINTER=y\n', config)

    def test_kconfig_reenabling_kunit_is_rejected(self):
        result, _ = self.configure('CONFIG_KUNIT=m\n', reenable=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Disabling CONFIG_KUNIT failed.', result.stdout)

    def test_local_builds_override_inherited_test_options(self):
        harness = '''
KUNIT_TEST=y
KUNIT_LOG=y
CONFIG_SCST_KUNIT_TEST=y
CONFIG_SCST_KUNIT_LOG=y
'''
        stub = '''
make() {
    printf '%s %s %s %s\\n' "$KUNIT_TEST" "$KUNIT_LOG" \\
        "$CONFIG_SCST_KUNIT_TEST" "$CONFIG_SCST_KUNIT_LOG"
}
compile_scst
'''
        result = subprocess.run(['bash', '-c', harness + PREAMBLE + COMPILE + stub],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.splitlines())
        self.assertEqual(set(result.stdout.splitlines()), {'n n n n'})


if __name__ == '__main__':
    unittest.main()
