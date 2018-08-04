#!/usr/bin/env python
"""
Setup file for fusnmp distribution.
"""
import sys
from setuptools import setup

VERSION = '1.0.3'

try:
    # Use pandoc to convert .md -> .rst when uploading to pypi
    import pypandoc
    DESCRIPTION = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError, OSError):
    DESCRIPTION = open('README.md').read()

if sys.version_info[0] == 2 and sys.version_info[1] < 7:
    sys.exit('Sorry, Python 2 < 2.7 is not supported')

if sys.version_info[0] == 3:
    sys.exit('Sorry, Python 3 < 3.3 is not supported')

setup(
    name='fusnmp',
    version=VERSION,
    description="A small but complete NetSNMP ctypes wrapper.",
    long_description=DESCRIPTION,
    keywords='snmp networking',
    author='Jon M. Dugan',
    author_email='jdugan@x1024.net',
    url='http://github.com/jdugan1024/fusnmp/',
    license='GPL',
    packages=["fusnmp"],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Topic :: Internet',
        'Operating System :: POSIX',
    ],
)
