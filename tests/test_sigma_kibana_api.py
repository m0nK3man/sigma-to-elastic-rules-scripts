import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import sigma_rules_menu as menu
from ui_text import set_language

from sigma_kibana_api import ApiError, KibanaClient, api_base, import_files, load_files

SCRIPT = Path(__file__).resolve().parents[1] / 'sigma_kibana_api.py'
MENU = SCRIPT.with_name('sigma_rules_menu.py')
TEST_KEY = 'encoded-test-key-fixture'


class StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.server.requests.append(('GET', self.path, dict(self.headers), None))
        self.reply(200, {'data': [], 'total': 0, 'page': 1, 'per_page': 1})

    def do_POST(self):
        payload = self.rfile.read(int(self.headers['Content-Length']))
        message = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {self.headers['Content-Type']}\r\nMIME-Version: 1.0\r\n\r\n".encode() + payload)
        part = list(message.iter_parts())[0]
        file_payload = part.get_payload(decode=True)
        self.server.requests.append(('POST', self.path, dict(self.headers), file_payload))
        self.server.part_name = part.get_param('name', header='content-disposition')
        count = len([line for line in file_payload.splitlines() if line.strip()])
        mode = self.server.mode
        if mode == 'redirect':
            self.send_response(302)
            self.send_header('Location', self.server.url + '/unexpected-redirect')
            self.end_headers()
        elif mode in {'401', '500'}:
            self.reply(int(mode), {'message': 'denied ' + TEST_KEY})
        elif mode == 'non_json':
            self.reply(200, b'<html>login</html>')
        elif mode == 'partial':
            self.reply(200, {'success': False, 'success_count': 0,
                             'errors': [{'rule_id': 'a', 'error': {'status_code': 409, 'message': 'duplicate'}}]})
        elif mode == 'missing_count':
            self.reply(200, {'success': True, 'errors': []})
        elif mode == 'connector_error':
            self.reply(200, {'success': True, 'success_count': count, 'errors': [],
                             'action_connectors_errors': [{'error': {'message': 'connector error'}}]})
        else:
            self.reply(200, {'success': True, 'success_count': count, 'rules_count': count,
                             'errors': [], 'exceptions_errors': [], 'exceptions_success': True})


class KibanaApiTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundles = self.root / 'bundles'
        self.bundles.mkdir()
        self.bundle = self.bundles / 'a.ndjson'
        self.bundle.write_text(json.dumps({'rule_id': 'a', 'enabled': False, 'name': 'Sigma test'}) + '\n')
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), StubHandler)
        self.server.requests = []
        self.server.mode = 'success'
        self.server.url = f'http://127.0.0.1:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.environment = patch.dict(os.environ, {'KIBANA_API_KEY': TEST_KEY, 'KIBANA_URL': self.server.url,
                                                  'KIBANA_SPACE': '', 'KIBANA_CA_CERT': '', 'SIGMA_LANGUAGE': 'vi'})
        self.environment.start()
        set_language('vi')
        self.addCleanup(self.environment.stop)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def run_cli(self, extra=(), input_text='', success=True, env=None):
        result = subprocess.run([sys.executable, str(SCRIPT), *extra], text=True,
                                input=input_text, capture_output=True, env=env, timeout=15)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_space_base_path_connection_and_api_key(self):
        result = self.run_cli(['--url', self.server.url + '/kibana', '--space', 'soc team', '--check'])
        method, path, headers, _ = self.server.requests[0]
        self.assertEqual(method, 'GET')
        self.assertEqual(path, '/kibana/s/soc%20team/api/detection_engine/rules/_find?per_page=1')
        self.assertEqual(headers['Authorization'], 'ApiKey ' + TEST_KEY)
        self.assertEqual({key.lower(): value for key, value in headers.items()}['kbn-xsrf'], 'sigma-splitter')
        self.assertIn('Đã kết nối', result.stdout)
        self.assertNotIn(TEST_KEY, result.stdout + result.stderr)

    def test_basic_auth(self):
        env = dict(os.environ, KIBANA_API_KEY='', KIBANA_USERNAME='fixture-user', KIBANA_PASSWORD='fixture-password')
        self.run_cli(['--check'], env=env)
        authorization = self.server.requests[0][2]['Authorization']
        self.assertEqual(authorization, 'Basic ' + base64.b64encode(b'fixture-user:fixture-password').decode())

    def test_multipart_disabled_payload_and_report(self):
        report = self.root / 'report.json'
        result = self.run_cli(['--file', str(self.bundle), '--space', 'soc', '--yes', '--report', str(report)])
        method, path, headers, payload = self.server.requests[0]
        self.assertEqual(method, 'POST')
        self.assertEqual(path, '/s/soc/api/detection_engine/rules/_import?overwrite=false')
        self.assertEqual(self.server.part_name, 'file')
        self.assertTrue(headers['Content-Type'].startswith('multipart/form-data; boundary='))
        self.assertEqual(payload, self.bundle.read_bytes())
        self.assertIs(json.loads(payload)['enabled'], False)
        data = json.loads(report.read_text())
        self.assertEqual(data['results'][0]['status'], 'imported')
        self.assertEqual(data['results'][0]['success_count'], 1)
        self.assertNotIn(TEST_KEY, result.stdout + result.stderr + report.read_text())

    def test_multiple_bundles_imported_sequentially(self):
        (self.bundles / 'b.ndjson').write_text(json.dumps({'rule_id': 'b', 'enabled': False}) + '\n')
        self.run_cli(['--bundles', str(self.bundles), '--yes'])
        self.assertEqual(len(self.server.requests), 2)
        self.assertEqual([json.loads(row[3])['rule_id'] for row in self.server.requests], ['a', 'b'])

    def test_validates_all_files_before_network(self):
        for bad in [b'not json\n', b'{"rule_id":"b","enabled":true}\n',
                    b'{"rule_id":"b"}\n', b'{"rule_id":"A","enabled":false}\n',
                    b'{"rule_id":123,"enabled":false}\n', b'[]\n', b'', b'\xff']:
            with self.subTest(bad=bad):
                (self.bundles / 'b.ndjson').write_bytes(bad)
                self.run_cli(['--bundles', str(self.bundles), '--yes'], success=False)
                self.assertEqual(self.server.requests, [])

    def test_dry_run_requires_no_credentials_and_sends_nothing(self):
        env = dict(os.environ, KIBANA_API_KEY='', KIBANA_USERNAME='', KIBANA_PASSWORD='')
        result = self.run_cli(['--bundles', str(self.bundles), '--dry-run'], env=env)
        self.assertIn('Chỉ xem thử', result.stdout)
        self.assertEqual(self.server.requests, [])
        self.assertEqual(list(self.root.glob('logs/*')), [])

    def test_cancel_sends_no_request_or_report(self):
        result = self.run_cli(['--file', str(self.bundle)], input_text='n\n')
        self.assertIn('Đã hủy import', result.stdout)
        self.assertEqual(self.server.requests, [])
        self.assertEqual(list(self.root.glob('logs/*')), [])

    def test_partial_200_stops_batch_and_reports_per_rule_errors(self):
        self.server.mode = 'partial'
        (self.bundles / 'b.ndjson').write_text(json.dumps({'rule_id': 'b', 'enabled': False}) + '\n')
        report = self.root / 'report.json'
        result = self.run_cli(['--bundles', str(self.bundles), '--yes', '--report', str(report)], success=False)
        self.assertEqual(len(self.server.requests), 1)
        records = json.loads(report.read_text())['results']
        self.assertEqual([record['status'] for record in records], ['failed', 'not_attempted'])
        self.assertIn('duplicate', result.stdout)
        self.assertIn('rule_id', result.stdout)

    def test_http_auth_failure_redacts_secret(self):
        self.server.mode = '401'
        report = self.root / 'report.json'
        result = self.run_cli(['--file', str(self.bundle), '--yes', '--report', str(report)], success=False)
        self.assertIn('HTTP 401', result.stdout)
        self.assertIn('[REDACTED]', result.stdout)
        self.assertNotIn(TEST_KEY, result.stdout + result.stderr + report.read_text())

    def test_redirect_is_blocked(self):
        self.server.mode = 'redirect'
        result = self.run_cli(['--file', str(self.bundle), '--yes'], success=False)
        self.assertIn('HTTP 302', result.stdout)
        self.assertEqual(len(self.server.requests), 1)

    def test_uncertain_responses_are_not_reported_as_success(self):
        for mode in ['non_json', 'missing_count', '500']:
            with self.subTest(mode=mode):
                self.server.mode = mode
                report = self.root / f'{mode}.json'
                self.run_cli(['--file', str(self.bundle), '--yes', '--report', str(report)], success=False)
                self.assertEqual(json.loads(report.read_text())['results'][0]['status'], 'unknown')

    def test_connector_errors_fail_import(self):
        self.server.mode = 'connector_error'
        result = self.run_cli(['--file', str(self.bundle), '--yes'], success=False)
        self.assertIn('connector error', result.stdout)

    def test_existing_report_is_not_overwritten_and_blocks_post(self):
        report = self.root / 'existing.json'
        report.write_text('keep me')
        self.run_cli(['--file', str(self.bundle), '--yes', '--report', str(report)], success=False)
        self.assertEqual(report.read_text(), 'keep me')
        self.assertEqual(self.server.requests, [])

    def test_timeout_marked_unknown_without_retry(self):
        client = KibanaClient(self.server.url)
        with patch.object(client.opener, 'open', side_effect=TimeoutError('fixture timeout')) as mocked:
            with contextlib.redirect_stdout(io.StringIO()):
                result = import_files(client, load_files(self.bundle), self.root / 'timeout.json')
        self.assertFalse(result)
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(json.loads((self.root / 'timeout.json').read_text())['results'][0]['status'], 'unknown')

    def test_interruption_preserves_unknown_status_in_report(self):
        client = KibanaClient(self.server.url)
        with patch.object(client, 'import_file', side_effect=KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                import_files(client, load_files(self.bundle), self.root / 'interrupted.json')
        self.assertEqual(json.loads((self.root / 'interrupted.json').read_text())['results'][0]['status'], 'unknown')

    def test_invalid_credentials_or_url_and_default_space(self):
        for url in ['http://user:password@example.org', 'ftp://example.org', 'https://example.org?token=x', '']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                api_base(url)
        self.assertEqual(api_base(self.server.url, 'default'), self.server.url)
        env = dict(os.environ, KIBANA_API_KEY='', KIBANA_USERNAME='', KIBANA_PASSWORD='')
        self.run_cli(['--check'], env=env, success=False)
        self.assertEqual(self.server.requests, [])

    def test_tls_context_is_verified_and_custom_ca_passed(self):
        import ssl
        with patch('sigma_kibana_api.ssl.create_default_context', wraps=ssl.create_default_context) as factory:
            client = KibanaClient(self.server.url)
        factory.assert_called_once_with(cafile=None)
        self.assertNotIn('unverified', repr(client.opener))
        with patch('sigma_kibana_api.ssl.create_default_context', return_value=ssl.create_default_context()) as factory:
            KibanaClient(self.server.url, ca_cert='/fixture/ca.pem')
        factory.assert_called_once_with(cafile='/fixture/ca.pem')

    def test_menu_connection_import_and_cancel(self):
        result = subprocess.run([sys.executable, str(MENU)],
                                input=f'10\n11\n{self.bundle}\nn\n11\n{self.bundle}\ny\n0\n',
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Đã kết nối', result.stdout)
        self.assertIn('Đã hủy import', result.stdout)
        self.assertIn('Đã import xong', result.stdout)
        self.assertEqual([request[0] for request in self.server.requests], ['GET', 'POST'])
        self.assertNotIn(TEST_KEY, result.stdout + result.stderr)

    def test_menu_url_and_space_configuration(self):
        result = subprocess.run([sys.executable, str(MENU)],
                                input=f'9\n{self.server.url}/kibana\nsoc\n\n10\n0\n',
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.server.requests[0][1], '/kibana/s/soc/api/detection_engine/rules/_find?per_page=1')

    def test_invalid_api_key_cannot_leak_via_header_errors(self):
        env = dict(os.environ, KIBANA_API_KEY='test-key\ninvalid')
        result = self.run_cli(['--check'], env=env, success=False)
        self.assertNotIn('test-key', result.stdout + result.stderr)
        self.assertEqual(self.server.requests, [])


    def test_ui_api_key_configuration_switches_auth_without_echo(self):
        new_key = 'new-test-key-fixture'
        output = io.StringIO()
        with patch.dict(os.environ, {'KIBANA_USERNAME': 'old-user', 'KIBANA_PASSWORD': 'old-password'}), \
             patch('builtins.input', return_value='1'), patch.object(sys.stdin, 'isatty', return_value=True), \
             patch('getpass.getpass', return_value=new_key) as hidden, contextlib.redirect_stdout(output):
            menu.configure_credentials()
            self.assertEqual(os.environ['KIBANA_API_KEY'], new_key)
            self.assertNotIn('KIBANA_USERNAME', os.environ)
            self.assertNotIn('KIBANA_PASSWORD', os.environ)
            KibanaClient(self.server.url).check_connection()
        hidden.assert_called_once()
        self.assertEqual(self.server.requests[0][2]['Authorization'], 'ApiKey ' + new_key)
        for secret in [new_key, TEST_KEY, 'old-password']:
            self.assertNotIn(secret, output.getvalue())

    def test_ui_basic_credentials_replace_api_key_and_reach_server(self):
        output = io.StringIO()
        with patch('builtins.input', side_effect=['2', 'fixture-user']), \
             patch.object(sys.stdin, 'isatty', return_value=True), \
             patch('getpass.getpass', return_value='fixture-password'), contextlib.redirect_stdout(output):
            menu.configure_credentials()
            self.assertNotIn('KIBANA_API_KEY', os.environ)
            KibanaClient(self.server.url).check_connection()
        token = base64.b64encode(b'fixture-user:fixture-password').decode()
        self.assertEqual(self.server.requests[0][2]['Authorization'], 'Basic ' + token)
        self.assertNotIn('fixture-password', output.getvalue())
        self.assertNotIn(token, output.getvalue())

    def test_ui_cancel_keeps_previous_credentials(self):
        with patch('builtins.input', return_value='1'), patch.object(sys.stdin, 'isatty', return_value=True), \
             patch('getpass.getpass', return_value=''), contextlib.redirect_stdout(io.StringIO()):
            menu.configure_credentials()
        self.assertEqual(os.environ['KIBANA_API_KEY'], TEST_KEY)

    def test_ui_clear_credentials_requires_reauthentication(self):
        with patch('builtins.input', return_value='3'), contextlib.redirect_stdout(io.StringIO()):
            menu.configure_credentials()
        for key in ('KIBANA_API_KEY', 'KIBANA_USERNAME', 'KIBANA_PASSWORD'):
            self.assertNotIn(key, os.environ)
        with self.assertRaises(ValueError):
            KibanaClient(self.server.url)

    def test_non_tty_credentials_are_not_read_with_echo(self):
        with patch('builtins.input', return_value='1'), patch.object(sys.stdin, 'isatty', return_value=False), \
             patch('getpass.getpass') as hidden, contextlib.redirect_stdout(io.StringIO()):
            menu.configure_credentials()
        hidden.assert_not_called()
        self.assertEqual(os.environ['KIBANA_API_KEY'], TEST_KEY)

    def test_hidden_input_failure_does_not_fall_back_to_echo(self):
        import getpass
        import warnings
        def failing_prompt(prompt):
            warnings.warn('fixture fallback', getpass.GetPassWarning)
            raise AssertionError('Echo fallback must not run')
        with patch.object(sys.stdin, 'isatty', return_value=True), \
             patch('getpass.getpass', side_effect=failing_prompt), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(menu.secret_input('Secret: '), '')

    def test_conversion_does_not_receive_kibana_credentials(self):
        source = self.root / 'rules'
        source.mkdir()
        config = {'sources': [str(source)], 'output': str(self.root / 'output'),
                  'tags': [], 'bundle_size': 500, 'sigma_bin': 'sigma', 'classify_only': True}
        result = subprocess.CompletedProcess([], 0, stdout='', stderr='')
        with patch('builtins.input', return_value='y'), \
             patch('sigma_rules_menu.subprocess.run', return_value=result) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            menu.run_splitter(config)
        environment = run.call_args.kwargs['env']
        for key in ('KIBANA_API_KEY', 'KIBANA_USERNAME', 'KIBANA_PASSWORD'):
            self.assertNotIn(key, environment)
        self.assertEqual(os.environ['KIBANA_API_KEY'], TEST_KEY)

    def test_english_api_output_and_menu_import(self):
        result = self.run_cli(['--language', 'en', '--check'])
        self.assertIn('Connected to', result.stdout)
        self.assertNotIn('Đã kết nối', result.stdout)
        result = subprocess.run([sys.executable, str(MENU), '--language', 'en'],
                                input=f'11\n{self.bundle}\ny\n0\n', text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Import complete.', result.stdout)
        self.assertIn('Import report:', result.stdout)
        self.assertNotIn('Báo cáo import', result.stdout)



if __name__ == '__main__':
    unittest.main()
