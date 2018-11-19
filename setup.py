import os
import runpy
from setuptools import setup, find_packages

pkg_name = 'vonx'
meta = runpy.run_path("./{}/version.py".format(pkg_name))
version = meta['__version__']

setup(
    name=pkg_name,
    packages=find_packages(),
    package_data={'': ['*.html', '*.yml']},
    include_package_data=True,
    version=version,
    description='VON-X Connector',
    license='Apache Software License',
    author='PSPC-SPAC',
    author_email='andrew@1crm.com',
    url='https://github.com/PSPC-SPAC-buyandsell/von-x/',
    download_url='https://github.com/PSPC-SPAC-buyandsell/von-x/archive/v{}.tar.gz'.format(version),
    keywords=['verified-organizations-network', 'VON', 'TheOrgBook', 'Hyperledger', 'Indy', 'HTTP'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
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
        'aiohttp-jinja2~=1.1.0',
        'didauth==1.2.3',
        'PyYAML',
        'networkx>=2.2,<3'
        'von-anchor==1.6.37',
    ],
)
