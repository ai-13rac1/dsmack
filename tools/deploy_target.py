"""Local source gate and project names for shared-webhost deployment."""
import subprocess

WEBHOST = 'https://pod.dstack.soc1024.com'
STAGING_HOST = 'https://private-agent-staging.dstack.soc1024.com'


def staging_page_url(origin):
    if origin not in (STAGING_HOST, WEBHOST):
        raise ValueError('staging origin must be the staging hostname or webhost')
    return origin + ('/private-agent-staging/' if origin == WEBHOST else '/')


def project_name(project, target):
    return project + ('-staging' if target == 'staging' else '')


def source_ref(repo, target, release_tag=None):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
    head = git('rev-parse', 'HEAD')
    if target == 'production':
        if git('status', '--porcelain', '--untracked-files=all'):
            raise ValueError('production requires a clean source tree')
        if release_tag:
            if not release_tag.startswith('private-agent-v') or '/' in release_tag:
                raise ValueError('release tag must name a private-agent version')
            tagged = git('rev-parse', '--verify', 'refs/tags/'+release_tag+'^{commit}')
            if tagged != head:
                raise ValueError('release tag must point exactly at HEAD')
            return head
        # Prefer the locally recorded GitHub main; never fetch or change remotes.
        for ref in ('refs/remotes/origin/main', 'refs/heads/main'):
            if subprocess.run(['git', '-C', str(repo), 'show-ref', '--verify', '--quiet', ref]).returncode == 0:
                break
        else:
            raise ValueError('production requires locally recorded origin/main or main')
        if subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', head, ref]).returncode != 0:
            raise ValueError('production HEAD must be contained in locally recorded main')
    return head
