"""
pysrvx setup
"""
from setuptools import setup

long_description = """\
pysrvx is a pure python client library implementation for the SrvX QServer
module. More more information on SrvX visit http://www.srvx.net
"""

setup(name='pysrvx',
      version='0.2',
      description='QServer client library',
      long_description=long_description,
      author='Gavin M. Roy',
      author_email='gmr@gamesurge.net',
      url='http://github.com/GameSurge/pysrvx/',
      packages=['pysrvx'],
      license='BSD',
      classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)',
        'Operating System :: OS Independent',
        'Topic :: Communications',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries',
        ],
        zip_safe=True
      )
