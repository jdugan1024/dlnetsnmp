from setuptools import setup, find_packages
import platform

VERSION = '0.4.1'

packages = find_packages('lib', exclude=['ez_setup', 'examples', 'tests'])
package_dir = {'': 'lib'}
package_data = {}
if platform.system().lower().startswith('win'):
    package_data['DLNetSNMP'] = ['windows-i386/*.dll']

setup(
    name='DLNetSNMP',
    version=VERSION,
    description="A small but complete NetSNMP ctypes wrapper.",
    long_description="""\
DLNetSNMP is a Python ctypes wrapper for the NetSNMP library written. 
It provides:
 - Synchronous and asynchronous "get", "getbulk", "walk" and "set" operations.
 - MIBs management: set/get MIBs paths, load new MIBs, get OID descriptions
   from MIBs, oid to name (and vice versa) translation tools.
 - Session management, internal asynchronous events management, pluggable logger
   and meaningful error reporting.
 - Multi-platform: runs under Linux (and I think other Unixes also), Windows and OS X.
""",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Topic :: Internet',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows :: Windows NT/2000',
    ],
    keywords='snmp dlevel dlnetsnmp',
    author='Alessandro Iob',
    author_email='alessandro.iob@dlevel.com',
    url='http://www.dlevel.com/products/opensource/dlnetsnmp',
    license='GPL',
    package_dir=package_dir,
    package_data=package_data,
    packages=packages,
    zip_safe=False, )
