import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

SCRIPT = Path(__file__).resolve().parents[1] / 'split_sigma_rules.py'

FAKE_SIGMA = r'''#!/usr/bin/env python3
import json, pathlib, sys, yaml
output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
source = pathlib.Path(sys.argv[sys.argv.index('--skip-unsupported') - 1])
pipeline = sys.argv[sys.argv.index('-p') + 1]
rows = []
for path in sorted(source.rglob('*')):
    if path.suffix.lower() not in {'.yml', '.yaml'}:
        continue
    rule = yaml.safe_load(path.read_text())
    mode = rule.get('test_mode', '')
    if mode == 'fail':
        output.write_text('{"enabled": true}\n')
        sys.exit(2)
    if mode == 'skip':
        continue
    if mode == 'invalid':
        output.write_text('not json\n')
        sys.exit(0)
    row = {'name': 'SIGMA - ' + rule['title'], 'rule_id': rule['id'],
           'enabled': True, 'query': 'test', 'tags': ['attack.t1059', 'backend:tag'],
           'test_pipeline': pipeline}
    if mode == 'wrong_id':
        row['rule_id'] = 'unexpected'
    if mode == 'shared_id':
        row['rule_id'] = 'backend-shared'
    if mode == 'bad_tags':
        row['tags'] = 'not a list'
    if mode == 'no_id':
        row.pop('rule_id')
    rows.append(row)
    if mode == 'duplicate':
        rows.append(row)
output.write_text(''.join(json.dumps(row) + '\n' for row in rows))
'''


class SplitSigmaRulesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.core = self.root / 'rules'
        self.emerging = self.root / 'rules-emerging-threats'
        self.core.mkdir()
        self.emerging.mkdir()
        self.fake = self.root / 'fake_sigma.py'
        self.fake.write_text(FAKE_SIGMA)
        self.fake.chmod(0o755)
        self.output = self.root / 'output'

    def add_rule(self, source, filename, rule_id, product='windows', category='process_creation',
                 service=None, mode='', tags=None, title=None):
        logsource = {'product': product, 'category': category}
        if service is not None:
            logsource['service'] = service
        rule = {'title': title or filename, 'id': rule_id, 'logsource': logsource,
                'tags': tags or ['attack.execution', 'attack.t1059', 'attack.t1059'],
                'detection': {'selection': {'field': 'value'}, 'condition': 'selection'},
                'test_mode': mode}
        path = source / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(rule))

    def run_script(self, sources=None, extra=(), success=True):
        command = [sys.executable, str(SCRIPT), '--output', str(self.output),
                   '--sigma-bin', str(self.fake)]
        for source in sources or [self.core]:
            command.extend(['--source', str(source)])
        result = subprocess.run(command + list(extra), text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def manifest(self):
        with (self.output / 'manifest.csv').open(newline='') as handle:
            return list(csv.DictReader(handle))

    def rows(self, directory):
        return [(path, json.loads(line)) for path in sorted((self.output / directory).rglob('*.ndjson'))
                for line in path.read_text().splitlines()]

    def test_multi_source_tags_bundles_and_duplicate_exclusion(self):
        for i in range(5):
            self.add_rule(self.core, f'w{i}.yml', f'core-{i}', service='sysmon')
        self.add_rule(self.emerging, 'win.yml', 'emerging-win', category='image_load')
        for product in ('macos', 'kubernetes', 'zeek'):
            self.add_rule(self.core, f'{product}.yaml', product, product)
        self.add_rule(self.emerging, 'linux.yml', 'linux', 'linux')
        self.add_rule(self.core, 'duplicate.yml', 'DUPLICATE')
        self.add_rule(self.emerging, 'duplicate.yml', 'duplicate', 'macos')
        self.run_script([self.core, self.emerging], ['--bundle-size', '2',
            '--tag', 'custom:environment=production', '--tag', 'custom:owner=security-team',
            '--tag', 'attack.t1059', '--tag', 'custom:owner=security-team'])
        manifest = self.manifest()
        summary = json.loads((self.output / 'summary.json').read_text())
        self.assertEqual(summary['status_counts'], {'converted': 9, 'duplicate_rule_id': 2, 'manual_review': 1})
        self.assertEqual(summary['total_bundle_rules'], summary['total_converted_rules'])
        details = self.rows('ndjson')
        bundles = self.rows('bundles')
        self.assertEqual(len(details), 9)
        self.assertEqual(len(bundles), 9)
        self.assertEqual({row['rule_id'] for _, row in details}, {row['rule_id'] for _, row in bundles})
        self.assertEqual(len({row['rule_id'] for _, row in bundles}), 9)
        expected_pipelines = {'windows': 'ecs_windows', 'macos': 'ecs_macos_esf',
                              'kubernetes': 'ecs_kubernetes', 'zeek': 'ecs_zeek_beats'}
        by_id = {record['rule_id'].lower(): record for record in manifest}
        for path, row in details + bundles:
            record = by_id[row['rule_id']]
            self.assertIs(row['enabled'], False)
            self.assertEqual(row['test_pipeline'], expected_pipelines[record['product']])
            tags = row['tags']
            self.assertEqual(tags[:2], ['attack.execution', 'attack.t1059'])
            self.assertIn('backend:tag', tags)
            self.assertEqual(len(tags), len(set(tags)))
            expected = ['custom:managed-by=sigma-splitter', f"custom:source={record['collection']}",
                        f"custom:product={record['product']}", f"custom:category={record['category']}",
                        f"custom:pipeline={record['pipeline']}"]
            if record['service'] != 'unspecified':
                expected.append(f"custom:service={record['service']}")
            self.assertEqual(json.loads(record['automatic_tags']), expected)
            for tag in expected + ['custom:environment=production', 'custom:owner=security-team']:
                self.assertIn(tag, tags)
            self.assertNotIn('duplicate', row['rule_id'].lower())
            if path.parent.name == 'bundles':
                self.assertIn(record['collection'] + '_' + record['product'], path.name)
                self.assertEqual(record['bundle_file'], path.relative_to(self.output).as_posix())
            else:
                self.assertEqual(path.parent.name, record['collection'])
        sizes = [len(path.read_text().splitlines()) for path in (self.output / 'bundles').glob('*.ndjson')]
        self.assertEqual(sorted(sizes), [1, 1, 1, 1, 1, 2, 2])
        with (self.output / 'manual-review' / 'duplicate-rule-ids.csv').open() as handle:
            duplicates = list(csv.DictReader(handle))
        self.assertEqual(len(duplicates), 2)
        self.assertEqual({row['collection'] for row in duplicates}, {'sigma-core', 'sigma-emerging-threats'})
        self.assertIn('linux.yml', (self.output / 'manual-review' / 'linux.txt').read_text())
        self.assertEqual(len(list((self.output / 'classified').rglob('*.y*ml'))), 12)

    def test_classify_only_preserves_duplicates_and_does_not_run_sigma(self):
        self.add_rule(self.core, 'win.yml', 'duplicate')
        self.add_rule(self.emerging, 'win.yml', 'DUPLICATE')
        self.add_rule(self.core, 'linux.yml', 'linux', 'linux')
        self.add_rule(self.emerging, 'mac.yml', 'mac', 'macos')
        self.run_script([self.core, self.emerging], ['--classify-only', '--sigma-bin', '/does/not/exist'])
        self.assertEqual(sorted(row['status'] for row in self.manifest()),
                         ['duplicate_rule_id', 'duplicate_rule_id', 'pending', 'pending'])
        self.assertEqual(self.rows('ndjson'), [])
        self.assertEqual(self.rows('bundles'), [])
        self.assertEqual(list((self.output / 'logs').rglob('*.log')), [])

    def test_refuses_existing_output_without_modification(self):
        self.add_rule(self.core, 'win.yml', 'win')
        self.output.mkdir()
        sentinel = self.output / 'existing.txt'
        sentinel.write_text('keep me')
        self.run_script(success=False)
        self.assertEqual(sentinel.read_text(), 'keep me')
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_accepts_empty_existing_output_and_default_bundle_size(self):
        self.add_rule(self.core, 'win.yml', 'win')
        self.output.mkdir()
        self.run_script()
        self.assertEqual(len(self.rows('bundles')), 1)

    def test_skipped_rule_and_same_title_different_ids(self):
        self.add_rule(self.core, 'a.yml', 'a', title='same')
        self.add_rule(self.core, 'b.yml', 'b', title='same', mode='skip')
        self.run_script()
        self.assertEqual({r['rule_id']: r['status'] for r in self.manifest()}, {'a': 'converted', 'b': 'skipped'})
        self.assertEqual(len(self.rows('bundles')), 1)

    def test_rejects_bad_conversion_outputs(self):
        for mode, status in [('fail', 'conversion_failed'), ('invalid', 'validation_failed'),
                             ('duplicate', 'validation_failed'), ('wrong_id', 'validation_failed'),
                             ('bad_tags', 'validation_failed'), ('no_id', 'validation_failed')]:
            with self.subTest(mode=mode):
                self.output = self.root / mode
                self.add_rule(self.core, 'win.yml', 'win', mode=mode)
                self.run_script(success=False)
                self.assertEqual(self.manifest()[0]['status'], status)
                self.assertEqual(self.rows('ndjson'), [])
                self.assertEqual(self.rows('bundles'), [])

    def test_duplicate_ids_within_one_source(self):
        self.add_rule(self.core, 'a.yml', 'same')
        self.add_rule(self.core, 'b.yml', 'SAME')
        self.run_script()
        self.assertTrue(all(row['status'] == 'duplicate_rule_id' for row in self.manifest()))
        self.assertEqual(self.rows('ndjson'), [])

    def test_invalid_yaml_is_manual_review(self):
        (self.core / 'bad.yml').write_text('title: [')
        self.run_script(extra=['--classify-only'])
        self.assertEqual(self.manifest()[0]['status'], 'manual_review')

    def test_invalid_arguments_and_source_output_overlap(self):
        self.add_rule(self.core, 'win.yml', 'win')
        for extra in (['--bundle-size', '0'], ['--bundle-size', '-1'], ['--output', str(self.core / 'output')]):
            with self.subTest(extra=extra):
                self.run_script(extra=extra, success=False)
                self.assertFalse(self.output.exists())
        self.run_script([self.core, self.core], success=False)
        self.assertFalse(self.output.exists())
        unknown = self.root / 'other'
        unknown.mkdir()
        self.run_script([unknown], success=False)
        self.assertFalse(self.output.exists())

    def test_repeated_runs_have_stable_tags_and_bundle_contents(self):
        self.add_rule(self.core, 'win.yml', 'win')
        self.run_script(extra=['--tag', 'custom:test=1'])
        first = [path.read_bytes() for path in sorted((self.output / 'bundles').glob('*'))]
        self.output = self.root / 'output2'
        self.run_script(extra=['--tag', 'custom:test=1'])
        self.assertEqual(first, [path.read_bytes() for path in sorted((self.output / 'bundles').glob('*'))])

    def test_default_bundle_boundary(self):
        for i in range(501):
            self.add_rule(self.core, f"{i:03d}.yml", f"id-{i}")
        self.run_script()
        sizes = [len(path.read_text().splitlines()) for path in sorted((self.output / 'bundles').glob('*'))]
        self.assertEqual(sizes, [500, 1])
        self.assertEqual(len(self.rows('ndjson')), 501)
        self.assertEqual(len(self.rows('bundles')), 501)

    def test_missing_sigma_binary_is_reported(self):
        self.add_rule(self.core, 'win.yml', 'win')
        self.run_script(extra=['--sigma-bin', '/does/not/exist'], success=False)
        self.assertEqual(self.manifest()[0]['status'], 'conversion_failed')
        self.assertEqual(self.rows('bundles'), [])

    def test_rejects_backend_duplicate_across_groups(self):
        self.add_rule(self.core, 'win.yml', None, mode='shared_id')
        self.add_rule(self.emerging, 'mac.yml', None, 'macos', mode='shared_id')
        self.run_script([self.core, self.emerging], success=False)
        self.assertEqual(sorted(row['status'] for row in self.manifest()), ['converted', 'validation_failed'])
        self.assertEqual(len(self.rows('ndjson')), 1)
        self.assertEqual(len(self.rows('bundles')), 1)

    def test_rejects_invalid_source_tags(self):
        self.add_rule(self.core, 'win.yml', 'win', tags='invalid')
        self.run_script(success=False)
        self.assertEqual(self.manifest()[0]['status'], 'validation_failed')
        self.assertEqual(self.rows('ndjson'), [])


    def test_windows_subfolder_excludes_siblings_and_preserves_collection(self):
        self.add_rule(self.core, 'windows/win.yml', 'win')
        self.add_rule(self.core, 'windows/process_creation/nested.yaml', 'nested')
        self.add_rule(self.core, 'linux/outside.yml', 'win', 'linux')
        (self.core / 'outside-invalid.yml').write_text('title: [')
        self.run_script([self.core / 'windows'])
        records = self.manifest()
        self.assertEqual(len(records), 2)
        self.assertEqual({row['source'] for row in records}, {'windows/win.yml', 'windows/process_creation/nested.yaml'})
        self.assertTrue(all(row['collection'] == 'sigma-core' and row['status'] == 'converted' for row in records))
        summary = json.loads((self.output / 'summary.json').read_text())
        self.assertEqual(summary['total_source_rules'], 2)
        self.assertEqual(summary['total_bundle_rules'], 2)
        self.assertFalse((self.output / 'manual-review' / 'linux.txt').exists())
        for _, rule in self.rows('bundles'):
            self.assertIn('custom:source=sigma-core', rule['tags'])
            self.assertIs(rule['enabled'], False)
        self.assertEqual(len(list((self.output / 'classified').rglob('*.y*ml'))), 2)

    def test_nested_subfolders_in_both_collections_classify_only(self):
        self.add_rule(self.core, 'windows/process_creation/win.yml', 'win')
        self.add_rule(self.core, 'windows/image_load/excluded.yml', 'win')
        self.add_rule(self.emerging, 'campaign/windows/emerging.yml', 'emerging')
        self.add_rule(self.emerging, 'linux/excluded.yml', 'emerging', 'linux')
        self.run_script([self.core / 'windows' / 'process_creation', self.emerging / 'campaign' / 'windows'],
                        ['--classify-only', '--sigma-bin', '/does/not/exist'])
        records = self.manifest()
        self.assertEqual(len(records), 2)
        self.assertEqual({row['collection'] for row in records}, {'sigma-core', 'sigma-emerging-threats'})
        self.assertTrue(all(row['status'] == 'pending' for row in records))
        self.assertEqual(self.rows('ndjson'), [])

    def test_rejects_repeated_collection_for_parent_and_child_sources(self):
        self.add_rule(self.core, 'windows/win.yml', 'win')
        self.run_script([self.core, self.core / 'windows'], success=False)
        self.assertFalse(self.output.exists())


    def test_two_folders_in_one_collection_do_not_collide(self):
        self.add_rule(self.core, 'windows/image_load/same.yml', 'image', category='image_load')
        self.add_rule(self.core, 'windows/process_creation/same.yml', 'process')
        self.add_rule(self.core, 'windows/excluded.yml', 'excluded')
        self.run_script([self.core / 'windows' / 'image_load', self.core / 'windows' / 'process_creation'])
        records = self.manifest()
        self.assertEqual({row['source'] for row in records},
                         {'windows/image_load/same.yml', 'windows/process_creation/same.yml'})
        self.assertEqual({row['status'] for row in records}, {'converted'})
        self.assertEqual({rule['rule_id'] for _, rule in self.rows('bundles')}, {'image', 'process'})
        self.assertEqual(len(list((self.output / 'classified').rglob('same.yml'))), 2)

    def test_duplicate_ids_across_selected_folders_are_excluded(self):
        self.add_rule(self.core, 'windows/image_load/a.yml', 'shared')
        self.add_rule(self.core, 'windows/process_creation/b.yml', 'SHARED')
        self.run_script([self.core / 'windows' / 'image_load', self.core / 'windows' / 'process_creation'])
        self.assertTrue(all(row['status'] == 'duplicate_rule_id' for row in self.manifest()))
        self.assertEqual(self.rows('bundles'), [])

    def test_separate_roots_for_the_same_collection_are_rejected(self):
        self.add_rule(self.core, 'a.yml', 'a')
        other = self.root / 'other' / 'rules'
        other.mkdir(parents=True)
        self.add_rule(other, 'a.yml', 'b')
        self.run_script([self.core, other], success=False)
        self.assertFalse(self.output.exists())



if __name__ == '__main__':
    unittest.main()
