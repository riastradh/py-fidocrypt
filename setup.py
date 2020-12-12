# -*- coding: utf-8 -*-

#  Copyright 2020 Taylor R Campbell
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


try:
    from setuptools import setup
    from setuptools.command.build_py import build_py
    from setuptools.command.sdist import sdist
except ImportError:
    from distutils.core import setup
    from distutils.command.build_py import build_py
    from distutils.command.sdist import sdist


def get_version():
    with open('VERSION', 'rb') as f:
        version = f.read().strip().decode('utf8')

    pkg_version = None
    full_version = None
    if version.endswith('+'):
        import re
        import subprocess
        version = version[:-1]
        expected_tag = 'v' + version
        description = subprocess.check_output([
            'git', 'describe', '--dirty', '--match', expected_tag,
        ]).decode('utf8')
        if description != expected_tag:
            match = re.match(r'^(v[^-]*)-([0-9]+)-(.*)$', description)
            assert match is not None
            tag, revision, commitdirty = match.groups()
            assert tag == expected_tag
            commitdirty = commitdirty.replace('-', '.')
            pkg_version = '%s.post%s' % (version, revision)
            full_version = '%s.post%s+%s' % (version, revision, commitdirty)
    pkg_version = pkg_version or version
    full_version = full_version or version

    assert '-' not in full_version, '%r' % (full_version,)
    assert '-' not in pkg_version, '%r' % (pkg_version,)
    assert '+' not in pkg_version, '%r' % (pkg_version,)

    return pkg_version, full_version


def write_version_py(path):
    try:
        with open(path, 'rb') as f:
            old = f.read().decode('utf8')
    except IOError:
        old = None
    new = '__version__ = %r\n' % (full_version,)
    if old != new:
        with open(path, 'wb') as f:
            f.write(new.encode('utf8'))


class local_build_py(build_py):
    def run(self):
        write_version_py(version_py)
        super(local_build_py, self).run()


class local_sdist(sdist):
    def make_release_tree(self, base_dir, files):
        import os
        sdist.make_release_tree(self, base_dir, files)
        version_path = os.path.join(base_dir, 'VERSION')
        print('updating %s' % (version_path,))
        # Write atomically and avoid rewriting the real one in place
        # because this may be a hard link.
        with open(version_path + '.tmp', 'wb') as f:
            f.write(b'%s\n' % (pkg_version.encode('utf8'),))
        os.rename(version_path + '.tmp', version_path)


pkg_version, full_version = get_version()
version_py = 'src/version.py'


setup(
    name='fidocrypt',
    version=pkg_version,
    description='FIDO-based digital signatures',
    author='Taylor R Campbell',
    author_email='campbell+fidocrypt@mumble.net',
    url='https://mumble.net/~campbell/fidocrypt',
    license='Apache License, Version 2.0',
    install_requires=['fido2>=0.8.1'],
    tests_require=['pytest'],
    packages=['fidocrypt', 'fidocrypt.test'],
    package_dir={'fidocrypt': 'src', 'fidocrypt.test': 'test'},
    cmdclass={
        'build_py': local_build_py,
        'sdist': local_sdist,
    },
)
