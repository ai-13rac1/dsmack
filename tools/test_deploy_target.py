"""Production's source gate uses real git history and never needs a remote fetch."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deploy_target import source_ref, project_name

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class SourceGateTests(unittest.TestCase):
    def test_clean_main_ancestor_passes_and_dirty_or_unmerged_source_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)
            def git(*args):
                return subprocess.check_output(['git', '-C', tmp, *args], text=True).strip()
            git('init', '-q')
            git('config', 'user.name', 'Fixture'); git('config', 'user.email', 'fixture@example.invalid')
            (repo/'source').write_text('first')
            git('add', '.'); git('commit', '-qm', 'first')
            first=source_ref(repo, 'staging')
            with self.assertRaisesRegex(ValueError, 'locally recorded'):
                source_ref(repo, 'production')
            git('update-ref', 'refs/heads/main', first)
            self.assertEqual(source_ref(repo, 'production'), first)
            (repo/'source').write_text('next')
            with self.assertRaisesRegex(ValueError, 'clean'):
                source_ref(repo, 'production')
            self.assertEqual(source_ref(repo, 'staging'), first)
            git('add', '.'); git('commit', '-qm', 'next')
            second=source_ref(repo, 'staging')
            with self.assertRaisesRegex(ValueError, 'contained'):
                source_ref(repo, 'production')
            git('update-ref', 'refs/remotes/origin/main', second)
            self.assertEqual(source_ref(repo, 'production'), second)
            git('checkout', '-q', '--detach', first)
            self.assertEqual(source_ref(repo, 'production'), first)
            (repo/'untracked').write_text('not reviewed')
            with self.assertRaisesRegex(ValueError, 'clean'):
                source_ref(repo, 'production')

    def test_staging_package_routes_page_to_separate_broker_and_tunnels(self):
        page=load('page_deploy', ROOT/'applications/private-agent-web/deploy.py')
        bundle=load('page_bundle', ROOT/'applications/private-agent-web/bundle.py')
        with tempfile.TemporaryDirectory() as tmp:
            dist=Path(tmp)
            (dist/'index.html').write_text('page')
            (dist/'config.json').write_text(json.dumps(dict(broker='https://pod.dstack.soc1024.com/relay-broker-staging', tunnels='https://private-agent-staging.dstack.soc1024.com/tunnels', brokerKey='staged-key')))
            public_config=dist.parent/(dist.name+'-staging.json')
            self.addCleanup(public_config.unlink)
            public_config.write_text(json.dumps(dict(broker='production', tunnels='production', brokerKey='staged-key')))
            data=bundle.payload(dist)
            own=bundle.cid(data)
            (dist/'page-bundle.tar').write_bytes(data)
            (dist/'index.html').write_text(f'<meta name="page-bundle-cid" content="{own}">page')
            with patch.object(page.subprocess, 'check_output', return_value=b'export default () => new Response("page");'):
                archive=page.package(dist, 'staging', public_config)
            with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as package:
                config=json.load(package.extractfile('dist/config.json'))
                self.assertEqual(package.extractfile('dist/page-bundle.tar').read(), data)
                self.assertEqual(package.extractfile('dist/config.json').read(), (dist/'config.json').read_bytes())
            public_config.write_text(json.dumps(dict(broker='production', tunnels='production', brokerKey='wrong-key')))
            with self.assertRaisesRegex(ValueError, 'Build with PAGE_CONFIG'):
                page.package(dist, 'staging', public_config)
            self.assertEqual(config['brokerKey'], 'staged-key')
            self.assertEqual(config['broker'], 'https://pod.dstack.soc1024.com/relay-broker-staging')
            self.assertEqual(config['tunnels'], 'https://private-agent-staging.dstack.soc1024.com/tunnels')
            self.assertEqual(project_name('private-agent', 'staging'), 'private-agent-staging')
            self.assertEqual(project_name('relay-broker', 'production'), 'relay-broker')

    def test_page_refuses_before_packaging_or_reading_credentials(self):
        page=load('page_deploy_gate', ROOT/'applications/private-agent-web/deploy.py')
        with patch('sys.argv', ['deploy.py', '--target', 'production', '--evidence', 'unused',
                                '--page-env', 'unused', '--registry-account', 'fixture', '--operator-token-sha256', 'a'*64]), \
             patch.object(page, 'source_ref', side_effect=ValueError('clean tree required')), \
             patch.object(page, 'token') as token, patch.object(page, 'package') as package:
            with self.assertRaisesRegex(ValueError, 'clean tree'):
                page.main()
            token.assert_not_called(); package.assert_not_called()

    def test_broker_staging_package_and_upload_use_separate_project_and_keep_idle_guard(self):
        from types import SimpleNamespace
        broker=load('broker_deploy_stage', ROOT/'applications/relay-broker/deploy-inference.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            config=root/'config.json'
            config.write_text(json.dumps(dict(payments={'chainId':31337}, inference=dict(origins=['production']), browser_origins=['production'])))
            def bundle(command, **kwargs):
                Path(command[-1]).write_text('export default {};')
            with patch.object(broker, 'source_ref', return_value='prepared-commit'), patch.object(broker.subprocess, 'run', side_effect=bundle):
                broker.prepare(SimpleNamespace(target='staging', config=config, operator_token_sha256='a'*64,
                                               encrypted_env=None, out=root/'prepared'))
            with tarfile.open(root/'prepared/relay-broker.tgz') as package:
                packed=json.load(package.extractfile('applications/relay-broker/config.json'))
            self.assertEqual(packed['browser_origins'], ['https://private-agent-staging.dstack.soc1024.com'])
            self.assertEqual(packed['inference']['origins'], packed['browser_origins'])
            paths=[]
            def api(path, **kwargs):
                paths.append(path)
                if path == '/_api/projects':
                    self.assertIn(b'"name": "relay-broker-staging"', kwargs['body'])
                    return dict(runtime='deno', isolation='shared', mode='dev')
                if path.endswith('/promote'):
                    return dict(mode='attested')
                return {}
            # Staging may deploy a preparation from an earlier commit.
            with patch.object(broker, 'source_ref', return_value='another-commit'), \
                 patch.object(broker, 'token', return_value='fixture-only'), \
                 patch.object(broker, 'client', return_value=api), patch.object(broker, 'wait_for_idle') as guard:
                broker.deploy(SimpleNamespace(target='staging', prepared=root/'prepared', evidence=root/'evidence',
                                              apply=True, url='local-fixture', wait_idle_minutes=1))
            self.assertEqual(paths, ['/_api/projects', '/_api/projects/relay-broker-staging/promote', '/relay-broker-staging/key'])
            guard.assert_called_once_with('local-fixture', 1)


if __name__ == '__main__':
    unittest.main()
