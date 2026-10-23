"""Read current parser models without running a compiler or Coccinelle."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from coccinelle import iterators, model
from coccinelle.source import macros


class ModelTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for cache in (macros, iterators.definitions, iterators.models):
            cache.cache_clear()
            self.addCleanup(cache.cache_clear)

    def test_iterator_reads_changed_definition_without_a_digest(self):
        source = self.root / 'iterator.h'
        source.write_text('#define each(i) for (i = 0; i < 17; i++)\n')
        catalog = self.root / 'iterators.json'
        catalog.write_text(json.dumps({'iterator.h': ['each']}))
        with patch.object(iterators, 'CATALOG', catalog):
            self.assertIn('17', iterators.definitions(self.root)[0]['body'])
            source.write_text('#define each(i) for (i = 0; i < 19; i++)\n')
            iterators.definitions.cache_clear()
            macros.cache_clear()
            self.assertIn('19', iterators.definitions(self.root)[0]['body'])
            source.unlink()
            iterators.definitions.cache_clear()
            macros.cache_clear()
            with self.assertRaises(FileNotFoundError):
                iterators.definitions(self.root)

    def test_iterator_rejects_object_like_or_ambiguous_definitions(self):
        source = self.root / 'iterator.h'
        catalog = self.root / 'iterators.json'
        catalog.write_text(json.dumps({'iterator.h': ['each']}))
        with patch.object(iterators, 'CATALOG', catalog):
            for text, message in (
                    ('#define each 1\n', 'Expected a function-like iterator'),
                    ('#if X\n#define each(i) for (;;)\n#else\n#define each(i) for (;;)\n#endif\n',
                     'Ambiguous Coccinelle macro')):
                source.write_text(text)
                iterators.definitions.cache_clear()
                macros.cache_clear()
                with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                    iterators.definitions(self.root)

    def test_declaration_models_keep_current_bodies(self):
        source = self.root / 'declarations.h'
        source.write_text('#define DECLARE(name) int name(void) { return 17; }\n')
        with patch.object(model, 'SOURCE_MACROS', {'declarations.h': ['DECLARE']}):
            self.assertEqual(model.source_definitions(self.root), source.read_text().rstrip())
            source.write_text(source.read_text().replace('17', '19'))
            macros.cache_clear()
            self.assertEqual(model.source_definitions(self.root), source.read_text().rstrip())

    def test_parser_hints_extend_installed_builtins(self):
        builtins = self.root / 'native.h'
        builtins.write_text('#define NATIVE keep\n')
        hints = self.root / 'hints.h'
        hints.write_text('#define PROJECT hint\n')
        output = self.root / 'combined.h'
        with patch.object(model, 'MACROS', hints), \
                patch.object(model, 'native_definitions', return_value='#define EACH(i) for (;;)\n'), \
                patch.object(model, 'source_definitions', return_value='#define DECLARE int declaration;'):
            options = model.prepare('spatch', ['--macro-file-builtins', str(builtins), '-D', 'report'],
                                    output)
        self.assertEqual(options, ['-D', 'report', '--macro-file-builtins', str(output)])
        for name in ('NATIVE', 'PROJECT', 'EACH', 'DECLARE'):
            self.assertIn('#define ' + name, output.read_text())


if __name__ == '__main__':
    unittest.main()
