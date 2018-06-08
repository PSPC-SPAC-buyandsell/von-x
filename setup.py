import os
from setuptools import setup


pkg_name = 'vonx'
version = '1.0.0'

setup(
    name=pkg_name,
    packages=[
        pkg_name,
        '{}.config'.format(pkg_name),
        '{}.services'.format(pkg_name),
        '{}.templates'.format(pkg_name),
        '{}.web'.format(pkg_name),
    ],
    package_data={'': ['*.html', '*.yml']},
    include_package_data=True,
    version=version,
    description='VON-X Connector',
    license='Apache Software License',
    author='PSPC-SPAC',
    author_email='',
    url='https://github.com/PSPC-SPAC-buyandsell/von-x/',
    download_url='https://github.com/PSPC-SPAC-buyandsell/von-x/archive/{}.tar.gz'.format(version),
    keywords=['verified-organizations-network', 'VON', 'TheOrgBook', 'Hyperledger', 'Indy', 'HTTP'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='>=3.5.3',
    install_requires=[
        'aiohttp~=3.3.0',
        'jinja2',
        'PyYAML',
        'von-agent==1.1.2',
    ],
)
