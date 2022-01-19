"""org-tool setup"""

from orgtool import __version__
from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='org-tool',
    version=__version__,
    description='Tools to manage AWS Organizations with code',
    long_description=long_description,
    url='https://gitlab.aws.dev/delhom/org-tool',
    author='Laurent Delhomme',
    author_email='delhom@amazon.com',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ],
    keywords='aws organizations',
    packages=find_packages(exclude=['scratch', 'notes']),
    install_requires=[
        'boto3',
        'docopt',
        'PyYAML',
        'passwordgenerator',
        'cerberus',
        'email_validator',
        'ruamel.yaml'
    ],
    package_data={
        'orgtool': [
            'data/*',
            'spec_init_data/*',
            'spec_init_data/spec.d/*'
        ],
    },
    entry_points={
        'console_scripts': [
            'orgtool=orgtool.orgs:main',
            'orgtoolaccounts=orgtool.accounts:main',
            'orgtoolauth=orgtool.auth:main',
            'orgtoolconfigure=orgtool.configure:main',
            'orgtoolloginprofile=orgtool.loginprofile:main',
            'orgtool-accessrole=orgtool.tools.accessrole:main',
            'orgtool-spec-init=orgtool.tools.spec_init:main'
        ],
    },

)
