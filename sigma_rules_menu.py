#!/usr/bin/env python3

import argparse
import csv
import getpass
import json
import os
import shlex
import subprocess
import sys
import warnings
from pathlib import Path

from split_sigma_rules import validate_sources
from sigma_kibana_api import KibanaClient, ApiError, api_base, load_files, import_files, default_report
from ui_text import tr, set_language

SPLITTER = Path(__file__).with_name('split_sigma_rules.py')


def read_value(prompt, default):
    return input(f'{prompt} [{default}]: ').strip() or default


def confirmed(prompt):
    return input(prompt).strip().lower() in {'y', 'yes', 'c', 'co', 'có'}


def choose_language():
    print('\n1. Tiếng Việt\n2. English')
    choice = input('Ngôn ngữ / Language [1]: ').strip()
    if choice not in {'', '1', '2'}:
        print('Chọn 1 hoặc 2 / Choose 1 or 2.')
        return
    set_language('en' if choice == '2' else 'vi')


def show_sources(sources):
    if not sources:
        print(tr('No sources yet. Choose 1 to add your first folder.'))
    for number, source in enumerate(sources, 1):
        print('  ' + tr('Source {number}: {path}', number=number, path=source))


def manage_sources(config):
    while True:
        print('\n' + tr('Sources'))
        show_sources(config['sources'])
        print(tr('1. Add a folder\n2. Remove a folder\n0. Back'))
        choice = input(tr('Your choice: ')).strip()
        if choice == '0':
            return
        if choice == '1':
            while True:
                path = input(tr('Folder to add (Enter to cancel): ')).strip()
                if not path:
                    break
                try:
                    sources = validate_sources(config['sources'] + [path])
                except (ValueError, OSError) as exc:
                    print(tr('Could not add this folder: {error}', error=exc))
                    continue
                config['sources'] = [str(source) for source, _, _ in sources]
                print(tr('Added source {number}: {path}', number=len(sources), path=sources[-1][0]))
                if not confirmed(tr('Add another folder? [y/N]: ')):
                    break
        elif choice == '2':
            number = input(tr('Source number to remove (Enter to cancel): ')).strip()
            if not number:
                continue
            try:
                index = int(number) - 1
                if not 0 <= index < len(config['sources']):
                    raise ValueError
                removed = config['sources'].pop(index)
                print(tr('Removed: {path}', path=removed))
            except ValueError:
                print(tr('That source number is not in the list.'))
        else:
            print(tr('Please choose one of the numbers shown above.'))


def show_config(config):
    print('\n' + tr('Current setup'))
    show_sources(config['sources'])
    print('  ' + tr('Output folder: {path}', path=config['output']))
    print('  ' + tr('Extra tags: {tags}', tags=', '.join(config['tags']) or tr('none')))
    print('  ' + tr('Rules per bundle: {size}', size=config['bundle_size']))
    print('  ' + tr('Mode: {mode}', mode=tr('Classify only' if config['classify_only'] else 'Classify and convert')))
    print('  ' + tr('Sigma executable: {path}', path=config['sigma_bin']))


def build_command(config):
    command = [sys.executable, str(SPLITTER.resolve())]
    for source in config['sources']:
        command.extend(['--source', str(Path(source).expanduser().resolve())])
    command.extend(['--output', str(Path(config['output']).expanduser().resolve()),
                    '--bundle-size', str(config['bundle_size']), '--sigma-bin', config['sigma_bin']])
    for tag in config['tags']:
        command.append(f'--tag={tag}')
    if config['classify_only']:
        command.append('--classify-only')
    return command


def show_results(output):
    summary_file = output / 'summary.json'
    if summary_file.is_file():
        summary = json.loads(summary_file.read_text(encoding='utf-8'))
        print('\n' + tr('Results'))
        print(tr('Source rules: {count}', count=summary['total_source_rules']))
        for status, count in summary['status_counts'].items():
            print(f'  {status}: {count}')
        print(tr('Converted rules: {count}', count=summary['total_converted_rules']))
        print(tr('Rules in bundles: {count}', count=summary['total_bundle_rules']))
        print(tr('Bundles: {count}', count=summary['bundle_count']))
    manifest = output / 'manifest.csv'
    if manifest.is_file():
        with manifest.open(encoding='utf-8', newline='') as handle:
            failures = [row for row in csv.DictReader(handle)
                        if row['status'] in {'conversion_failed', 'validation_failed'}]
        for row in failures[:10]:
            print(tr('Rule error {source}: {error}', source=f"{row['collection']}/{row['source']}", error=row['notes']))
        if len(failures) > 10:
            print(tr('{count} more errors are listed in manifest.csv.', count=len(failures) - 10))
    print('\n' + tr('Output: {path}', path=output))
    for name in ('manifest.csv', 'summary.json', 'bundles', 'logs', 'manual-review'):
        if (output / name).exists():
            print(f'  {output / name}')


def run_splitter(config):
    try:
        if not SPLITTER.is_file():
            raise ValueError(tr('Splitter script is missing: {path}', path=SPLITTER))
        validate_sources(config['sources'], config['output'])
    except (ValueError, OSError) as exc:
        print(tr('Cannot start yet: {error}', error=exc))
        return
    show_config(config)
    command = build_command(config)
    print(tr('Command: {command}', command=shlex.join(command)))
    if not confirmed(tr('Start with this setup? [y/N]: ')):
        print(tr('Cancelled. No output was created.'))
        return
    print(tr('Working on your rules. This may take a few minutes...'))
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False,
                                env={name: value for name, value in os.environ.items()
                                     if name not in {'KIBANA_API_KEY', 'KIBANA_USERNAME', 'KIBANA_PASSWORD'}})
    except OSError as exc:
        print(tr('Could not start the splitter: {error}', error=exc))
        return
    if result.returncode == 0:
        print(tr('Conversion finished. Review the manifest before importing.'))
    else:
        print(tr('Conversion stopped with exit code {code}.', code=result.returncode))
        print((result.stderr or result.stdout).strip())
    try:
        show_results(Path(config['output']).expanduser().resolve())
    except (OSError, ValueError, KeyError) as exc:
        print(tr('Could not read the report: {error}', error=exc))


def secret_input(prompt):
    if not sys.stdin.isatty():
        print(tr('Hidden input requires an interactive terminal. Please run the menu in your terminal.'))
        return ''
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning:
        print(tr('Hidden input requires an interactive terminal. Please run the menu in your terminal.'))
        return ''


def configure_credentials():
    method = ('API key is set' if os.environ.get('KIBANA_API_KEY') else
              'Username/password are set' if os.environ.get('KIBANA_USERNAME') and os.environ.get('KIBANA_PASSWORD') else
              'Not configured')
    print(tr('Authentication: {method}', method=tr(method)))
    print(tr('1. API key\n2. Username and password\n3. Clear credentials\n0. Back'))
    choice = input(tr('Your choice: ')).strip()
    values = None
    if choice == '1':
        key = secret_input(tr('Encoded API key (hidden; Enter to cancel): ')).strip()
        if key:
            if any(ord(char) < 32 or ord(char) > 126 for char in key):
                print(tr('Use an encoded API key without control characters.'))
                return
            values = {'KIBANA_API_KEY': key}
    elif choice == '2':
        username = input(tr('Username (Enter to cancel): ')).strip()
        if username:
            if ':' in username:
                print(tr('Username must not contain a colon.'))
                return
            password = secret_input(tr('Password (hidden; Enter to cancel): '))
            if password:
                values = {'KIBANA_USERNAME': username, 'KIBANA_PASSWORD': password}
    elif choice == '3':
        values = {}
    elif choice != '0':
        print(tr('Please choose one of the numbers shown above.'))
        return
    if values is None:
        print(tr('No changes were made.'))
        return
    for name in ('KIBANA_API_KEY', 'KIBANA_USERNAME', 'KIBANA_PASSWORD'):
        os.environ.pop(name, None)
    os.environ.update(values)
    print(tr('Credentials updated for this menu session. They are not saved to disk or your parent shell.'
             if values else 'Credentials cleared for this menu session.'))


def configure_kibana(settings):
    try:
        default_url = api_base(settings['url'])
    except ValueError:
        default_url = ''
    url = read_value(tr('Kibana URL (include https:// or http://)'), default_url)
    space = input(tr('Space ID (Enter for default): ')).strip()
    ca_cert = input(tr('CA certificate path (Enter for system CA): ')).strip()
    try:
        api_base(url, space)
    except ValueError as exc:
        print(tr('Could not use that setup: {error}', error=exc))
        return
    settings.update(url=url, space=space, ca_cert=ca_cert)
    os.environ.update(KIBANA_URL=url, KIBANA_SPACE=space, KIBANA_CA_CERT=ca_cert)
    print(tr('Kibana address updated.'))


def use_kibana(settings, output, check=False):
    try:
        if check:
            KibanaClient(**settings).check_connection()
            return
        target = read_value(tr('NDJSON file or bundles folder'), str(Path(output) / 'bundles'))
        files = load_files(target)
        client = KibanaClient(**settings)
        print(tr('Target: {target}', target=client.base))
        print(tr('{files} files, {rules} Disabled rules; overwrite=false.', files=len(files), rules=sum(count for _, _, count in files)))
        for path, _, count in files:
            print(f'  {path.name}: {count}')
        if not confirmed(tr('Import into this Kibana target? [y/N]: ')):
            print(tr('Import cancelled. No files were sent.'))
            return
        succeeded = import_files(client, files, default_report(target))
        print(tr('Import complete.' if succeeded else 'Import is incomplete. Review the report above before trying again.'))
    except (ApiError, ValueError, OSError) as exc:
        print(tr('API error: {error}', error=exc))


def main():
    parser = argparse.ArgumentParser(description='Interactive Sigma conversion and Kibana import.')
    parser.add_argument('--language', choices=['vi', 'en'], default=os.environ.get('SIGMA_LANGUAGE'))
    args = parser.parse_args()
    config = {'sources': [], 'output': './sigma-separated', 'tags': [], 'bundle_size': 500,
              'classify_only': False, 'sigma_bin': 'sigma'}
    kibana = {'url': os.environ.get('KIBANA_URL', ''), 'space': os.environ.get('KIBANA_SPACE', ''),
              'ca_cert': os.environ.get('KIBANA_CA_CERT', '')}
    try:
        set_language(args.language) if args.language else choose_language()
        print(tr('Sigma Splitter'))
        print(tr('Paths are relative to the folder where you started the menu.'))
        while True:
            show_config(config)
            print('\n' + tr('1. Manage sources\n2. Output folder\n3. Extra tags\n4. Bundle size\n5. Switch conversion mode\n6. Sigma executable\n7. Preview command\n8. Run conversion\n9. Kibana address and Space\n10. Test Kibana connection\n11. Import bundles\n12. Kibana credentials\n13. Change language\n0. Exit'))
            choice = input(tr('Your choice: ')).strip()
            if choice == '0':
                print(tr('Goodbye.'))
                return 0
            if choice == '1':
                manage_sources(config)
            elif choice == '2':
                config['output'] = read_value(tr('Output folder'), config['output'])
            elif choice == '3':
                print(tr('Enter one tag per line. A blank line finishes and replaces the previous extra tags.'))
                tags = []
                while True:
                    tag = input(tr('Tag: ')).strip()
                    if not tag:
                        break
                    if tag not in tags:
                        tags.append(tag)
                config['tags'] = tags
            elif choice == '4':
                value = input(tr('Maximum rules per bundle: ')).strip()
                try:
                    size = int(value)
                    if size < 1:
                        raise ValueError
                    config['bundle_size'] = size
                except ValueError:
                    print(tr('Please enter a positive integer. The previous value is unchanged.'))
            elif choice == '5':
                config['classify_only'] = not config['classify_only']
            elif choice == '6':
                config['sigma_bin'] = read_value(tr('Executable name or path'), config['sigma_bin'])
            elif choice == '7':
                print(tr('Command: {command}', command=shlex.join(build_command(config))))
            elif choice == '8':
                run_splitter(config)
            elif choice == '9':
                configure_kibana(kibana)
            elif choice == '10':
                use_kibana(kibana, config['output'], check=True)
            elif choice == '11':
                use_kibana(kibana, config['output'])
            elif choice == '12':
                configure_credentials()
            elif choice == '13':
                choose_language()
            else:
                print(tr('Please choose one of the numbers shown above.'))
    except (EOFError, KeyboardInterrupt):
        print('\n' + tr('The menu was stopped. If a request was in progress, check the output and Kibana before retrying.'))
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
