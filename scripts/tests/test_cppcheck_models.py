"""Check native-model fixture failure reporting without running native tools."""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cppcheck import compiler, test_models


class ModelFixtureTests(unittest.TestCase):
    def test_failed_compiler_probe_keeps_commands_and_output_in_suite_log(self):
        directories = []

        def failed(command, *, input, cwd, stdout, stderr, **kwargs):
            directories.append(Path(cwd))
            stdout.write(b'partial builtin output\n')
            stderr.write(b'cc: fatal error: fixture compiler configuration\n')
            return subprocess.CompletedProcess(command, 1)

        output = io.StringIO()
        case = test_models.NativeModelTests()
        with (patch.object(test_models.shutil, 'which', side_effect=lambda name: '/fixture/' + name),
              patch.object(compiler, 'run', side_effect=failed),
              patch.object(test_models.subprocess, 'run') as native,
              contextlib.redirect_stderr(output)):
            with self.assertRaisesRegex(ValueError, 'Compiler context probe failed'):
                case.check('void fixture(void) {}\n')
        native.assert_not_called()
        self.assertEqual(len(directories), 1)
        self.assertFalse(directories[0].exists())
        for expected in ('fixture.c', 'void fixture(void)', 'compiler-1-builtins.json',
                         '"command"', '/fixture/cc', '"status": 1',
                         'partial builtin output', 'cc: fatal error: fixture compiler configuration'):
            self.assertIn(expected, output.getvalue())

    def test_trace_finding_must_reference_the_tested_invocation(self):
        case = test_models.NativeModelTests()
        context = {'standard': 'c11', 'definitions': []}

        def result(command, **kwargs):
            path = Path(command[-1])
            file, line = str(path), 1
            if scenario == 'other file':
                file = str(path.with_name('other.c'))
            elif scenario == 'other line':
                line = 2
            xml = (f'<results><errors><error id="arrayIndexOutOfBounds">'
                   f'<location file="{file}" line="{line}"/>'
                   '</error></errors></results>')
            return subprocess.CompletedProcess(command, 3, '', xml)

        with (patch.object(test_models.shutil, 'which', return_value='/fixture/tool'),
              patch.object(test_models.CompilerContext, 'get', return_value=context),
              patch.object(test_models.CompilerContext, 'save'),
              patch.object(test_models.subprocess, 'run', side_effect=result),
              contextlib.redirect_stderr(io.StringIO())):
            for scenario in ('invocation', 'other file', 'other line'):
                with self.subTest(scenario=scenario):
                    if scenario == 'invocation':
                        case.check('int values[2];', 'arrayIndexOutOfBounds', expected_lines=range(1, 2))
                    else:
                        with self.assertRaises(AssertionError):
                            case.check('int values[2];', 'arrayIndexOutOfBounds',
                                       expected_lines=range(1, 2))


if __name__ == '__main__':
    unittest.main()
