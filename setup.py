#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='asyncenocean',
    version='0.50.1',
    description='EnOcean serial protocol implementation',
    author='Matthias Urlichs',
    author_email='matthias@urlichs.de',
    url='https://github.com/M-o-a-T/asyncenocean',
    packages=[
        'asyncenocean',
        'asyncenocean.protocol',
        'asyncenocean.communicators',
    ],
    scripts=[
        'examples/enocean_example.py',
    ],
    package_data={
        '': ['EEP.xml']
    },
    install_requires=[
        'enum-compat>=0.0.2',
        'anyio_serial',
        'beautifulsoup4>=4.3.2',
    ])
