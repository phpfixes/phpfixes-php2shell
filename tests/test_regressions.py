"""Security regressions and boundaries of the free directory diagnostic."""
import copy
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/phpfixes-php2shell'
sys.path.insert(0, str(SKILL / 'php2shell'))
import assess
import inventory

NOW = dt.datetime(2026, 10, 23, 12, tzinfo=dt.timezone.utc)


def evidence():
    data = json.loads((SKILL / 'examples/ubuntu-backport.json').read_text())
    data['collected_at'] = NOW.isoformat()
    return data


def package_version(data, version, php_version=None):
    runtime = data['runtimes'][0]
    runtime['package']['version'] = version
    runtime['running']['package_version'] = version
    if php_version is not None:
        runtime['php_version'] = php_version
        runtime['running']['php_version'] = php_version
    return data


class ReleaseIdentityTests(unittest.TestCase):
    def assert_unknown(self, data):
        row = assess.assess(data, NOW)['runtimes'][0]
        self.assertEqual(row['installed_assessment'], 'UNKNOWN')
        self.assertEqual(row['running_assessment'], 'UNKNOWN')
        self.assertTrue(row['needed_evidence'])

    def test_ubuntu_aliases_cannot_bypass_backport_lineage(self):
        cases = [('8.3.6+private-0ubuntu0.24.04.13', '8.3.6'),
                 ('08.3.6-0ubuntu0.24.04.13+local', '08.3.6'),
                 ('８.3.6-0ubuntu0.24.04.13+local', '８.3.6'),
                 ('8.3.6-0ubuntu0.24.04.13+local', '8.3.6'),
                 ('8.3.6-0ubuntu0.24.04.013', '8.3.6'),
                 ('00:8.3.6-0ubuntu0.24.04.13', '8.3.6'),
                 ('9x:8.3.6-0ubuntu0.24.04.13', '8.3.6')]
        for version, php in cases:
            with self.subTest(version=version):
                self.assert_unknown(package_version(evidence(), version, php))

    def test_the_same_aliases_cannot_reach_the_generic_upstream_package_path(self):
        for manager, origin in (('apt', 'sury'), ('rpm', 'remi'), ('apk', 'distro'), ('brew', 'distro')):
            for upstream in ('08.3.36', '８.3.36', '8.3.36+private'):
                with self.subTest(manager=manager, upstream=upstream):
                    data = evidence()
                    runtime = data['runtimes'][0]
                    runtime['origin'] = origin
                    runtime['package'].update(manager=manager, repository=origin if origin != 'distro' else 'ubuntu')
                    php = '8.3.36' if '+' in upstream else upstream
                    suffix = '_1' if manager == 'brew' else '-r1' if manager == 'apk' else '-1'
                    self.assert_unknown(package_version(data, upstream + suffix, php))

    def test_upstream_provenance_does_not_canonicalize_a_release_alias(self):
        for php in ('08.3.36', '8.03.36', '8.3.036', '８.3.36'):
            with self.subTest(php=php):
                data = evidence()
                runtime = data['runtimes'][0]
                runtime.update(origin='upstream', package=None, php_version=php)
                runtime['running'].pop('package_version')
                runtime['running']['php_version'] = php
                data['evidence'].append({'id': 'build', 'kind': 'build-provenance', 'text': 'Synthetic exact build claim.'})
                runtime['evidence_ids'].append('build')
                self.assert_unknown(data)

    def test_primary_advisories_settle_only_two_exact_old_debian_builds(self):
        cases = [('12', '8.2', '8.2.32-1~deb12u1', 'DLA-4848-1'),
                 ('13', '8.4', '8.4.24-1~deb13u1', 'DSA-6574-1')]
        for os_version, branch, version, advisory in cases:
            with self.subTest(version=version):
                data = evidence()
                runtime = data['runtimes'][0]
                runtime['os'] = {'id': 'debian', 'version_id': os_version}
                runtime['package'].update(name='php' + branch + '-fpm', repository='debian')
                package_version(data, version, version.split('-')[0])
                row = assess.assess(data, NOW)['runtimes'][0]
                self.assertEqual(row['installed_assessment'], 'AFFECTED')
                self.assertEqual(row['running_assessment'], 'AFFECTED')
                self.assertIn(advisory, row['source_urls'][0])
                for unknown_version in (version + '+local', version.replace('-1~', '-2~')):
                    self.assert_unknown(package_version(copy.deepcopy(data), unknown_version))

    def test_unlisted_debian_bases_and_revisions_do_not_inherit_fix(self):
        for version in ('8.2.35-2~deb12u1', '8.2.35-1~deb13u1', '8.2.36-1~deb12u1',
                        '8.2.35-1~deb12u01', '8.2.35+private-1~deb12u1'):
            with self.subTest(version=version):
                data = evidence()
                runtime = data['runtimes'][0]
                runtime['os'] = {'id': 'debian', 'version_id': '12'}
                runtime['package'].update(name='php8.2-fpm', repository='debian')
                php = version.split('-')[0].split('+')[0]
                self.assert_unknown(package_version(data, version, php))


class MalformedTimeTests(unittest.TestCase):
    def test_utc_conversion_overflow_is_an_ordinary_input_error(self):
        for value in ('0001-01-01T00:00:00+23:59', '9999-12-31T23:59:59-23:59'):
            with self.subTest(value=value):
                with self.assertRaises(assess.EvidenceError):
                    assess.timestamp(value, 'collected_at')
                data = evidence()
                data['collected_at'] = value
                saved = json.loads((SKILL / 'examples/local-inventory.json').read_text())
                saved['collected_at'] = value
                with tempfile.TemporaryDirectory() as temp:
                    for script, flag, payload in (('assess.py', '--evidence', data), ('inventory.py', '--input', saved)):
                        path = Path(temp) / 'input.json'
                        path.write_text(json.dumps(payload))
                        run = subprocess.run([sys.executable, '-I', str(SKILL / 'php2shell' / script), flag, str(path)],
                                             cwd=temp, text=True, capture_output=True)
                        self.assertEqual(run.returncode, 2, run.stderr)
                        self.assertNotIn('Traceback', run.stderr)
                        self.assertEqual(run.stdout, '')


class DirectoryScopeTests(unittest.TestCase):
    def test_diagnostic_reports_do_not_recommend_a_plan_or_link_a_purchase(self):
        data = evidence()
        for version in ('8.3.6-0ubuntu0.24.04.12', '8.3.6-0ubuntu0.24.04.13'):
            report = assess.assess(package_version(copy.deepcopy(data), version), NOW)
            self.assertFalse({'handoff', 'proposed_plan', 'proposed_plan_reason'} & set(report))
            self.assertNotIn('https://phpfixes.com/', json.dumps(report))
        saved = json.loads((SKILL / 'examples/local-inventory.json').read_text())
        self.assertNotIn('https://phpfixes.com/', json.dumps(inventory.diagnose(saved, NOW)))

    def test_the_public_cli_has_no_commercial_action_options(self):
        path = str(SKILL / 'examples/ubuntu-backport.json')
        for option, value in (('--plan', 'patch'), ('--catalog', path), ('--source', 'codex')):
            run = subprocess.run([sys.executable, '-I', str(SKILL / 'php2shell/assess.py'), '--evidence', path, option, value],
                                 cwd=str(ROOT), text=True, capture_output=True)
            self.assertEqual(run.returncode, 2)
            self.assertIn('unrecognized arguments', run.stderr)
            self.assertEqual(run.stdout, '')
        for relative in ('php2shell/service_handoff.py', 'data/service-checks.schema.json', 'examples/service-checks-paused.json'):
            self.assertFalse((SKILL / relative).exists())


if __name__ == '__main__':
    unittest.main()
