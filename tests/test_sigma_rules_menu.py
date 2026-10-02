import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from test_split_sigma_rules import FAKE_SIGMA

MENU = Path(__file__).resolve().parents[1] / 'sigma_rules_menu.py'
SPLITTER = MENU.with_name('split_sigma_rules.py')


class SigmaRulesMenuTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sigma menu ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.core = self.root / 'rules'
        self.emerging = self.root / 'rules-emerging-threats'
        self.core.mkdir()
        self.emerging.mkdir()
        self.fake = self.root / 'fake sigma.py'
        self.fake.write_text(FAKE_SIGMA)
        self.fake.chmod(0o755)
        self.output = self.root / 'menu output'
        self.add_rule(self.core, 'win.yml', 'core-win')
        self.add_rule(self.core, 'linux.yml', 'core-linux', 'linux')
        self.add_rule(self.emerging, 'win.yml', 'emerging-win')

    def add_rule(self, source, filename, identifier, product='windows', mode=''):
        rule = {'title': filename, 'id': identifier,
                'logsource': {'product': product, 'category': 'process_creation'},
                'tags': ['attack.execution'], 'test_mode': mode,
                'detection': {'selection': {'field': 'value'}, 'condition': 'selection'}}
        (source / filename).write_text(yaml.safe_dump(rule))

    def run_menu(self, inputs, code=0, language='vi'):
        result = subprocess.run([sys.executable, str(MENU), '--language', language], cwd=self.root,
                                input='\n'.join(inputs) + '\n', text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stderr)
        return result.stdout

    def configure(self):
        return ['1', '1', str(self.core), 'y', str(self.emerging), 'n', '0',
                '2', str(self.output), '6', str(self.fake)]

    def rows(self, directory):
        return [json.loads(line) for path in sorted(directory.rglob('*.ndjson'))
                for line in path.read_text().splitlines()]

    def test_conversion_matches_cli_with_tags_and_bundle_size(self):
        tags = ['custom:owner=security team', 'custom:batch=20261002']
        output = self.run_menu(self.configure() + ['3', tags[0], tags[0], tags[1], '',
                                                  '4', '1', '7', '8', 'y', '0'])
        self.assertIn('Đã xử lý xong', output)
        self.assertIn('manual_review: 1', output)
        self.assertIn('Số bundle: 2', output)
        menu_rows = self.rows(self.output / 'bundles')
        self.assertEqual(len(menu_rows), 2)
        for row in menu_rows:
            self.assertIs(row['enabled'], False)
            for tag in tags:
                self.assertIn(tag, row['tags'])
            self.assertEqual(len(row['tags']), len(set(row['tags'])))
        cli_output = self.root / 'cli output'
        command = [sys.executable, str(SPLITTER), '--source', str(self.core),
                   '--source', str(self.emerging), '--output', str(cli_output),
                   '--sigma-bin', str(self.fake), '--bundle-size', '1']
        for tag in tags:
            command.extend(['--tag', tag])
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(menu_rows, self.rows(cli_output / 'bundles'))
        self.assertEqual((self.output / 'manifest.csv').read_bytes(), (cli_output / 'manifest.csv').read_bytes())

    def test_classify_only_single_collection_and_clear_tags(self):
        output = self.run_menu(['1', '1', str(self.core), 'n', '0', '2', str(self.output),
                               '3', 'custom:test=old', '', '3', '',
                               '6', '/does/not/exist', '5', '8', 'có', '0'])
        self.assertIn('pending: 2', output)
        self.assertEqual(self.rows(self.output / 'bundles'), [])
        with (self.output / 'manifest.csv').open() as handle:
            records = list(csv.DictReader(handle))
        self.assertEqual({row['collection'] for row in records}, {'sigma-core'})
        self.assertTrue(all(row['additional_tags'] == '[]' for row in records))
        self.assertEqual(list((self.output / 'logs').rglob('*.log')), [])

    def test_cancel_does_not_create_output(self):
        output = self.run_menu(self.configure() + ['8', '', '0'])
        self.assertIn('Đã hủy. Chưa tạo', output)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        sentinel = self.output / 'existing.txt'
        sentinel.write_text('keep me')
        output = self.run_menu(self.configure() + ['8', '0'])
        self.assertIn('Chưa thể bắt đầu', output)
        self.assertNotIn('Bắt đầu với cấu hình này', output)
        self.assertEqual(list(self.output.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_text(), 'keep me')

    def test_invalid_input_keeps_old_configuration(self):
        output = self.run_menu(['invalid', '4', '0', '4', '-2', '4', 'text',
                               '1', 'invalid', '0', '4', '2', '7', '0'])
        self.assertEqual(output.count('Giá trị cũ vẫn được giữ lại.'), 3)
        self.assertIn('--bundle-size 2', output)
        self.assertIn('Bạn chọn một trong các số', output)
        self.assertFalse(self.output.exists())

    def test_missing_source_is_reported(self):
        output = self.run_menu(['1', '1', str(self.root / 'missing' / 'rules-emerging-threats'), '', '0', '8', '0'])
        self.assertIn('Không tìm thấy thư mục nguồn', output)
        self.assertNotIn('Bắt đầu với cấu hình này', output)

    def test_conversion_failure_is_visible(self):
        self.add_rule(self.core, 'win.yml', 'core-win', mode='fail')
        output = self.run_menu(self.configure() + ['8', 'y', '0'])
        self.assertIn('Quá trình xử lý gặp lỗi, mã thoát 1', output)
        self.assertIn('conversion_failed: 1', output)
        self.assertIn('Lỗi rule sigma-core/win.yml:', output)
        self.assertIn(str(self.output / 'logs'), output)
        self.assertEqual(len(self.rows(self.output / 'bundles')), 1)

    def test_paths_and_tags_are_not_executed_as_shell(self):
        self.output = self.root / '$(touch UNEXPECTED)'
        output = self.run_menu(self.configure() + ['3', '$(touch TAG_EXECUTED)', '-literal', '',
                                                  '8', 'y', '0'])
        self.assertIn('Đã xử lý xong', output)
        self.assertTrue(self.output.is_dir())
        self.assertFalse((self.root / 'UNEXPECTED').exists())
        self.assertFalse((self.root / 'TAG_EXECUTED').exists())
        for row in self.rows(self.output / 'bundles'):
            self.assertIn('$(touch TAG_EXECUTED)', row['tags'])
            self.assertIn('-literal', row['tags'])

    def test_eof_exits_without_writing_output(self):
        result = subprocess.run([sys.executable, str(MENU), '--language', 'vi'], cwd=self.root, input='',
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 130)
        self.assertIn('Đã dừng', result.stdout)
        self.assertFalse(self.output.exists())

    def test_menu_selects_only_windows_subfolder(self):
        windows = self.core / 'windows'
        windows.mkdir()
        self.add_rule(windows, 'chosen.yml', 'chosen')
        self.add_rule(self.core, 'outside.yml', 'chosen', 'linux')
        output = self.run_menu(['1', '1', str(windows), 'n', '0', '2', str(self.output),
                               '6', str(self.fake), '8', 'y', '0'])
        self.assertIn('Tổng rule nguồn: 1', output)
        self.assertIn('converted: 1', output)
        rows = self.rows(self.output / 'bundles')
        self.assertEqual([row['rule_id'] for row in rows], ['chosen'])
        self.assertIn('custom:source=sigma-core', rows[0]['tags'])
        with (self.output / 'manifest.csv').open() as handle:
            records = list(csv.DictReader(handle))
        self.assertEqual(records[0]['source'], 'windows/chosen.yml')
        self.assertEqual(len(records), 1)

    def test_menu_emerging_subfolder_classify_only(self):
        windows = self.emerging / 'campaign' / 'windows'
        windows.mkdir(parents=True)
        self.add_rule(windows, 'chosen.yml', 'chosen')
        output = self.run_menu(['1', '1', str(windows), 'n', '0', '2', str(self.output),
                               '5', '6', '/does/not/exist', '8', 'y', '0'])
        self.assertIn('pending: 1', output)
        with (self.output / 'manifest.csv').open() as handle:
            records = list(csv.DictReader(handle))
        self.assertEqual(records[0]['collection'], 'sigma-emerging-threats')
        self.assertEqual(len(records), 1)
        self.assertEqual(self.rows(self.output / 'bundles'), [])


    def test_add_remove_then_add_sources_in_english(self):
        output = self.run_menu(['1', '1', str(self.core), 'y', str(self.emerging), 'n',
                               '2', '1', '1', str(self.core), 'n', '0', '2', str(self.output),
                               '6', str(self.fake), '8', 'y', '0'], language='en')
        self.assertIn('Added source 1:', output)
        self.assertIn('Added source 2:', output)
        self.assertIn('Removed:', output)
        self.assertIn('Conversion finished', output)
        self.assertNotIn('Cấu hình hiện tại', output)
        self.assertEqual(len(self.rows(self.output / 'bundles')), 2)

    def test_language_can_be_changed_during_menu_session(self):
        output = self.run_menu(['13', '2', '0'])
        self.assertIn('Cấu hình hiện tại', output)
        self.assertIn('Current setup', output)
        self.assertIn('Goodbye.', output)

    def test_duplicate_or_overlapping_source_is_not_added(self):
        windows = self.core / 'windows'
        windows.mkdir()
        output = self.run_menu(['1', '1', str(self.core), 'y', str(windows), '', '0', '7', '0'], language='en')
        self.assertIn('These source folders overlap', output)
        self.assertNotIn('Added source 2:', output)
        self.assertIn('--source', output)

    def test_menu_converts_two_folders_in_one_collection(self):
        first = self.core / 'windows' / 'image_load'
        second = self.core / 'windows' / 'process_creation'
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        self.add_rule(first, 'same.yml', 'image')
        self.add_rule(second, 'same.yml', 'process')
        output = self.run_menu(['1', '1', str(first), 'y', str(second), 'n', '0',
                               '2', str(self.output), '6', str(self.fake), '8', 'y', '0'])
        self.assertIn('Tổng rule nguồn: 2', output)
        self.assertEqual({row['rule_id'] for row in self.rows(self.output / 'bundles')}, {'image', 'process'})



if __name__ == '__main__':
    unittest.main()
