"""Offline regressions for upstream scripts; all responses/credentials are synthetic."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(os.environ.get('AUDIT_SOURCE', str(Path(__file__).resolve().parent.parent))).resolve()
SCRIPTS = SOURCE / 'skills/auditoria-seguranca/scripts'
NODE = shutil.which('node')
PRIVATE = 'AUDIT_FAKE_PRIVATE_RESPONSE_NOT_REAL'
KEY = 'sb_secret_AUDIT_FAKE_VALUE_NOT_A_WORKING_KEY'


class ScriptRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = self.root / 'fixture.env'
        self.env.write_text('SUPABASE_URL=https://audit-fixture.invalid\nSUPABASE_ANON_KEY=sb_publishable_fixture_not_real\n')
        self.stub = self.root / 'fetch-stub.mjs'
        self.stub.write_text('''
import { readFileSync, appendFileSync } from 'node:fs';
const fixture = JSON.parse(readFileSync(process.env.AUDIT_FIXTURE, 'utf8'));
globalThis.fetch = async (url, options = {}) => {
  appendFileSync(process.env.AUDIT_REQUESTS, JSON.stringify({url, method: options.method || 'GET', headers: options.headers, redirect:options.redirect, body:options.body, timeout_signal:!!options.signal}) + '\\n');
  return new Response(fixture.body, {status: fixture.status, headers: fixture.headers || {}});
};
''')

    def node_script(self, name, args, body, status=403, headers=None):
        fixture = self.root / 'response.json'
        fixture.write_text(json.dumps({'body': body, 'status': status, 'headers': headers or {}}))
        scope = self.root / 'scope.json'
        scope.write_text(json.dumps(getattr(self, 'scope_override', None) or {'version':1, 'origin':'https://audit-fixture.invalid', 'disposable_environment':True, 'requests':[
            {'path':'/functions/v1/fixture','method':'GET','fixture_only':True},
            {'path':'/rest/v1/fixture?select=*&limit=5','method':'GET'},
            {'path':'/rest/v1/rpc/fixture','method':'GET','fixture_only':True}]}))
        args = [*args, '--scope', scope, *(['--execute'] if getattr(self, 'execute', True) else [])]
        requests = self.root / 'requests.jsonl'
        env = dict(os.environ, AUDIT_FIXTURE=str(fixture), AUDIT_REQUESTS=str(requests))
        result = subprocess.run([NODE, '--import', str(self.stub), str(SCRIPTS / name), *map(str, args)],
                                env=env, cwd=self.root, capture_output=True, text=True, timeout=15)
        return result, [json.loads(x) for x in requests.read_text().splitlines()] if requests.exists() else []

    def cases(self, forbidden=None):
        cases = self.root / 'cases.json'
        cases.write_text(json.dumps([{'nome': 'fixture', 'caminho': '/functions/v1/fixture',
                                     'esperado': [403], 'nao_conter': forbidden or []}]))
        return cases

    def test_endpoint_does_not_log_response_content(self):
        result, calls = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], PRIVATE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(PRIVATE not in result.stdout + result.stderr, 'Synthetic private response was logged')

    def test_endpoint_checks_forbidden_text_after_preview_boundary(self):
        result, _ = self.node_script('conferir-endpoints.mjs', [self.env, self.cases(['cpf'])], 'x' * 400 + 'cpf')
        self.assertEqual(result.returncode, 1, 'Sensitive marker after byte 300 was ignored')

    def test_endpoint_keeps_expected_status_and_failure_exit(self):
        for status, expected in [(403, 0), (200, 1)]:
            with self.subTest(status=status):
                result, _ = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], '{}', status)
                self.assertEqual(result.returncode, expected)

    def test_secret_search_omits_values_and_prefixes(self):
        project = self.root / 'project'
        project.mkdir()
        (project / 'config.ts').write_text(f'const VITE_SERVICE_ROLE_KEY = "{KEY}";\n')
        result = subprocess.run(['bash', str(SCRIPTS / 'procurar-segredos.sh'), str(project)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertIn('config.ts', result.stdout)
        self.assertTrue(KEY not in result.stdout + result.stderr, 'Synthetic full secret was logged')
        self.assertTrue(KEY[:10] not in result.stdout + result.stderr, 'Synthetic secret prefix was logged')

    def deno_script(self, deno_exit, function_present=True):
        project = self.root / 'project'
        project.mkdir(exist_ok=True)
        if function_present:
            function = project / 'supabase/functions/fixture'
            function.mkdir(parents=True)
            (function / 'index.ts').write_text('export const fixture = true;\n')
        bins = self.root / 'bin'
        bins.mkdir(exist_ok=True)
        deno = bins / 'deno'
        deno.write_text(f'#!/bin/sh\necho "TS9999: synthetic type checker fixture"\nexit {deno_exit}\n')
        deno.chmod(0o700)
        return subprocess.run(['bash', str(SCRIPTS / 'deno-check-todas.sh'), str(project), str(self.root / 'logs')],
                              env=dict(os.environ, PATH=str(bins) + os.pathsep + os.environ['PATH']),
                              capture_output=True, text=True, timeout=15)

    def test_deno_failure_propagates_to_exit_status(self):
        result = self.deno_script(1)
        self.assertIn('1 com erro', result.stdout)
        self.assertEqual(result.returncode, 1, 'Checker failure did not fail the wrapper')

    def test_deno_success_is_preserved(self):
        result = self.deno_script(0)
        self.assertEqual(result.returncode, 0)
        self.assertIn('1 ok', result.stdout)

    def test_deno_zero_functions_is_not_a_clean_run(self):
        result = self.deno_script(0, function_present=False)
        self.assertEqual(result.returncode, 2, 'Empty coverage was treated as a successful check')

    def test_visitor_report_omits_synthetic_row_values(self):
        targets = self.root / 'targets.json'
        targets.write_text(json.dumps({'rows': [{'tipo': 'tabela', 'nome': 'fixture'}]}))
        output = self.root / 'report.json'
        result, calls = self.node_script('teste-visitante.mjs', [self.env, targets, output],
                                        json.dumps([{'email': 'fixture@example.invalid', 'secret': PRIVATE}]),
                                        200, {'content-range': '0-0/1'})
        self.assertEqual(result.returncode, 0)
        report = output.read_text()
        self.assertTrue(PRIVATE not in report + result.stdout + result.stderr, 'Raw row value leaked')
        self.assertIn('email', report)
        self.assertEqual(len(calls), 1)

    def test_default_plan_never_fetches(self):
        self.execute = False
        r, calls = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], '{}')
        self.assertEqual(r.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn('PLANO', r.stdout)

    def test_rejects_secret_and_non_anon_jwt_before_network(self):
        import base64
        payload = base64.urlsafe_b64encode(b'{"role":"service_role"}').decode().rstrip('=')
        for key in [KEY, 'eyJhbGciOiJIUzI1NiJ9.' + payload + '.fake_signature']:
            self.env.write_text('SUPABASE_URL=https://audit-fixture.invalid\nSUPABASE_ANON_KEY=' + key + '\n')
            r, calls = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], '{}')
            self.assertEqual(r.returncode, 2)
            self.assertEqual(calls, [])
            self.assertNotIn(key, r.stdout + r.stderr)

    def test_rejects_unrelated_origin_before_network(self):
        self.env.write_text('SUPABASE_URL=https://unrelated.invalid\nSUPABASE_ANON_KEY=sb_publishable_fixture_not_real\n')
        r, calls = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], '{}')
        self.assertEqual(r.returncode, 2)
        self.assertEqual(calls, [])

    def test_prevalidates_entire_plan_before_first_request(self):
        cases = self.cases()
        data = json.loads(cases.read_text())
        cases.write_text(json.dumps(data + [dict(data[0], caminho='/functions/v1/other')]))
        r, calls = self.node_script('conferir-endpoints.mjs', [self.env, cases], '{}')
        self.assertEqual(r.returncode, 2)
        self.assertEqual(calls, [])

    def test_rejects_unreviewed_effects(self):
        self.scope_override = {'version':1, 'origin':'https://audit-fixture.invalid', 'requests':[
            {'path':'/functions/v1/fixture','method':'GET'}]}
        r, calls = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], '{}')
        self.assertEqual(r.returncode, 2)
        self.assertEqual(calls, [])

    def test_bounded_response_is_indeterminate_without_body_log(self):
        r, calls = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], PRIVATE + 'x' * 1048576)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn(PRIVATE, r.stdout + r.stderr)
        self.assertEqual(len(calls), 1)

    def test_publishable_key_only_apikey_get_has_no_body(self):
        r, calls = self.node_script('conferir-endpoints.mjs', [self.env, self.cases()], '{}')
        self.assertEqual(r.returncode, 0)
        self.assertNotIn('Authorization', calls[0]['headers'])
        self.assertNotIn('body', calls[0])
        self.assertEqual(calls[0]['redirect'], 'error')
        self.assertTrue(calls[0]['timeout_signal'])

    def test_visitor_scalar_rpc_is_analyzed_without_values(self):
        targets = self.root / 'targets.json'
        targets.write_text(json.dumps({'rows':[{'tipo':'funcao','nome':'fixture','nargs':0,'volatil':'s'}]}))
        output = self.root / 'scalar.json'
        r, calls = self.node_script('teste-visitante.mjs', [self.env, targets, output], '"fixture@example.invalid"', 200)
        self.assertEqual(r.returncode, 0)
        data = json.loads(output.read_text())
        self.assertEqual(data['funcoes_chamadas'][0]['itens'], 1)
        self.assertTrue(data['funcoes_chamadas'][0]['padroes_encontrados'])
        self.assertNotIn('fixture@example.invalid', output.read_text() + r.stdout)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_installer_has_no_package_execution(self):
        bins = self.root / 'bin'
        bins.mkdir()
        fake = bins / 'npx'
        fake.write_text('#!/bin/sh\nexit 98\n')
        fake.chmod(0o700)
        r = subprocess.run(['bash', str(SOURCE / 'instalar.sh')], env=dict(os.environ, PATH=str(bins)+os.pathsep+os.environ['PATH']), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn('PLANO LOCAL', r.stdout)


if __name__ == '__main__':
    unittest.main()
