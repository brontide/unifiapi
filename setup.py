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
