#!/usr/bin/env python3

import argparse
import base64
import json
import os
import ssl
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from ui_text import tr, set_language


class ApiError(RuntimeError):
    def __init__(self, message, uncertain=False):
        super().__init__(message)
        self.uncertain = uncertain


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_base(url, space=''):
    parsed = urlsplit(url)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError(tr('Kibana URL must include http:// or https:// and must not contain credentials, a query, or a fragment.'))
    base = url.rstrip('/')
    if space and space != 'default':
        base += '/s/' + quote(space, safe='')
    return base


def auth_from_env():
    key = os.environ.get('KIBANA_API_KEY', '')
    username = os.environ.get('KIBANA_USERNAME', '')
    password = os.environ.get('KIBANA_PASSWORD', '')
    if key:
        if any(ord(char) < 32 or ord(char) > 126 for char in key):
            raise ValueError(tr('Use an encoded API key without control characters.'))
        return 'ApiKey ' + key, [key]
    if username and password:
        token = base64.b64encode(f'{username}:{password}'.encode()).decode()
        return 'Basic ' + token, [password, token]
    raise ValueError(tr('Set an API key or both a username and password. In the menu, choose Kibana credentials.'))


class KibanaClient:
    def __init__(self, url, space='', ca_cert=None, timeout=30):
        self.base = api_base(url, space)
        self.authorization, self.secrets = auth_from_env()
        if timeout <= 0:
            raise ValueError(tr('Timeout must be greater than zero.'))
        self.timeout = timeout
        context = ssl.create_default_context(cafile=ca_cert or None)
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=context))

    def redact(self, text):
        text = str(text)
        for secret in [self.authorization, *sorted(self.secrets, key=len, reverse=True)]:
            if secret:
                text = text.replace(secret, '[REDACTED]')
                text = text.replace(json.dumps(secret)[1:-1], '[REDACTED]')
        return text[:2000]

    def request(self, path, data=None, content_type=None):
        headers = {'Authorization': self.authorization, 'kbn-xsrf': 'sigma-splitter',
                   'Accept': 'application/json'}
        if content_type:
            headers['Content-Type'] = content_type
        request = Request(self.base + path, data=data, headers=headers,
                          method='POST' if data is not None else 'GET')
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
        except HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')
            raise ApiError(f'HTTP {exc.code}: {self.redact(body)}',
                           uncertain=data is not None and exc.code >= 500) from None
        except (URLError, OSError, TimeoutError) as exc:
            raise ApiError(tr('Connection error: {error}', error=self.redact(exc)), uncertain=data is not None) from None
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ApiError(tr('The API did not return valid JSON. Check the Kibana URL and reverse proxy.'),
                           uncertain=data is not None) from None
        if not isinstance(result, dict):
            raise ApiError(tr('The API response is not a JSON object.'), uncertain=data is not None)
        return result

    def check_connection(self):
        result = self.request('/api/detection_engine/rules/_find?per_page=1')
        if not isinstance(result.get('data'), list):
            raise ApiError(tr('This is not a Detection Rules API response.'))
        print(tr('Connected to {target}; Detection Rules API is readable.', target=self.base))
        print(tr('Read access does not confirm import permission.'))

    def import_file(self, path, payload):
        boundary = 'sigma-' + uuid.uuid4().hex
        filename = quote(path.name, safe='._-')
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                f'filename="{filename}"\r\nContent-Type: application/x-ndjson\r\n\r\n').encode()
        body += payload + f'\r\n--{boundary}--\r\n'.encode()
        return self.request('/api/detection_engine/rules/_import?overwrite=false', body,
                            f'multipart/form-data; boundary={boundary}')


def load_files(target):
    target = Path(target).expanduser().resolve()
    paths = sorted(target.glob('*.ndjson')) if target.is_dir() else [target]
    if not paths:
        raise ValueError(tr('No NDJSON files found in: {path}', path=target))
    seen = set()
    files = []
    for path in paths:
        if not path.is_file() or path.suffix.lower() != '.ndjson':
            raise ValueError(tr('Not an NDJSON file: {path}', path=path))
        payload = path.read_bytes()
        count = 0
        for number, line in enumerate(payload.decode('utf-8').splitlines(), 1):
            if not line.strip():
                continue
            try:
                rule = json.loads(line)
            except ValueError:
                raise ValueError(tr('{file}, line {line}: invalid JSON.', file=path.name, line=number)) from None
            if not isinstance(rule, dict) or rule.get('enabled') is not False:
                raise ValueError(tr('{file}, line {line}: every rule must have enabled=false.', file=path.name, line=number))
            rule_id = rule.get('rule_id')
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError(tr('{file}, line {line}: a nonempty rule_id is required.', file=path.name, line=number))
            identifier = rule_id.strip().lower()
            if identifier in seen:
                raise ValueError(tr('Duplicate rule ID in the selected files: {rule_id}', rule_id=rule_id))
            seen.add(identifier)
            count += 1
        if not count:
            raise ValueError(tr('File contains no rules: {path}', path=path))
        files.append((path, payload, count))
    return files


def import_files(client, files, report_path):
    records = [{'file': str(path), 'expected_count': count, 'status': 'not_attempted',
                'success_count': 0, 'errors': []} for path, _, count in files]
    report = Path(report_path).expanduser().resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the report before the first POST; never overwrite a previous import report.
    with report.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps({'target': client.base, 'results': records}, ensure_ascii=False, indent=2))
        handle.flush()
        for record, (path, payload, count) in zip(records, files):
            print(tr('Importing {file}: {count} rules...', file=path.name, count=count))
            record['status'] = 'unknown'
            record['errors'] = [tr('Request started; no confirmed result yet.')]
            handle.seek(0)
            json.dump({'target': client.base, 'results': records}, handle, ensure_ascii=False, indent=2)
            handle.truncate()
            handle.flush()
            try:
                response = client.import_file(path, payload)
                errors = []
                for field in ('errors', 'exceptions_errors', 'action_connectors_errors'):
                    values = response.get(field, [])
                    if not isinstance(values, list):
                        raise ApiError(tr('Invalid response field: {field}.', field=field), uncertain=True)
                    errors.extend(client.redact(json.dumps(value, ensure_ascii=False)) for value in values)
                success_count = response.get('success_count')
                if type(success_count) is not int or success_count < 0 or success_count > count:
                    raise ApiError(tr('The API response has no valid success_count.'), uncertain=True)
                record['success_count'] = success_count
                record['errors'] = errors
                succeeded = (response.get('success') is True and success_count == count and not errors
                             and response.get('exceptions_success', True) is not False
                             and response.get('action_connectors_success', True) is not False)
                record['status'] = 'imported' if succeeded else 'failed'
                if not succeeded and not errors:
                    record['errors'] = [tr('The API has not confirmed that all rules were imported.')]
            except ApiError as exc:
                record['status'] = 'unknown' if exc.uncertain else 'failed'
                record['errors'] = [client.redact(exc)]
            handle.seek(0)
            json.dump({'target': client.base, 'results': records}, handle, ensure_ascii=False, indent=2)
            handle.truncate()
            handle.flush()
            print('  ' + tr('{status}: {done}/{count} rules', status=record['status'], done=record['success_count'], count=count))
            for error in record['errors']:
                print(f'  {error}')
            if record['status'] != 'imported':
                print(tr('Stopped this batch. Remaining files were not sent; no automatic retry.'))
                break
    print(tr('Import report: {path}', path=report))
    return all(record['status'] == 'imported' for record in records)


def default_report(target):
    target = Path(target).expanduser().resolve()
    parent = target.parent
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    return parent / 'logs' / f'kibana-import-{stamp}.json'


def main():
    parser = argparse.ArgumentParser(description='Check Kibana connection or import Disabled Sigma NDJSON bundles.')
    parser.add_argument('--language', choices=['vi', 'en'], default=os.environ.get('SIGMA_LANGUAGE', 'en'))
    parser.add_argument('--url', default=os.environ.get('KIBANA_URL', ''))
    parser.add_argument('--space', default=os.environ.get('KIBANA_SPACE', ''))
    parser.add_argument('--ca-cert', default=os.environ.get('KIBANA_CA_CERT', ''))
    parser.add_argument('--timeout', type=float, default=30)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--file', type=Path)
    mode.add_argument('--bundles', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--yes', action='store_true', help='Confirm import without an interactive prompt.')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    set_language(args.language)
    try:
        if args.check:
            KibanaClient(args.url, args.space, args.ca_cert, args.timeout).check_connection()
            return 0
        target = args.file or args.bundles
        if args.file and not args.file.expanduser().is_file():
            raise ValueError(tr('--file must point to an NDJSON file.'))
        if args.bundles and not args.bundles.expanduser().is_dir():
            raise ValueError(tr('--bundles must point to a bundles folder.'))
        files = load_files(target)
        base = api_base(args.url, args.space)
        print(tr('Target: {target}', target=base))
        print(tr('{files} files, {rules} Disabled rules; overwrite=false.', files=len(files), rules=sum(count for _, _, count in files)))
        for path, _, count in files:
            print('  ' + tr('{file}: {count} rules', file=path.name, count=count))
        if args.dry_run:
            print(tr('Dry run: no connection or upload was made.'))
            return 0
        client = KibanaClient(args.url, args.space, args.ca_cert, args.timeout)
        if not args.yes and input(tr('Import into this Kibana target? [y/N]: ')).strip().lower() not in {'y', 'yes', 'c', 'co', 'có'}:
            print(tr('Import cancelled. No files were sent.'))
            return 0
        return 0 if import_files(client, files, args.report or default_report(target)) else 1
    except (ApiError, ValueError, OSError) as exc:
        print(tr('Error: {error}', error=exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print(tr('Stopped. If a POST was started, check Kibana before retrying.'), file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
