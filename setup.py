'''THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

# Bitcoin Cash (BCH)   qpz32c4lg7x7lnk9jg6qg7s4uavdce89myax5v5nuk
# Ether (ETH) -        0x843d3DEC2A4705BD4f45F674F641cE2D0022c9FB
# Litecoin (LTC) -     Lfk5y4F7KZa9oRxpazETwjQnHszEPvqPvu
# Bitcoin (BTC) -      34L8qWiQyKr8k4TnHDacfjbaSqQASbBtTd

# contact :- github@jamessawyer.co.uk



from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='unifiapi',
      version='0.3',
      description='Bare-bones json interaction with Ubiquiti controllers',
      long_description=readme(),
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7.5',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.6',
      ],
      keywords='UBNT controller unifi',
      url='http://github.com/brontide/unifiapi',
      author='Eric Warnke',
      author_email='ericew@gmail.com',
      license='MIT',
      packages=['unifiapi'],
      install_requires=[
          'requests',
          'PyYAML',
          'future',
      ],
      #      entry_points={
      #          'console_scripts': ['unificmd=unifiapi.cmd:main'],
      #      },
      include_package_data=True,
      zip_safe=False)
