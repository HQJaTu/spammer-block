from setuptools import setup, find_packages

setup(
    name='spammer-block',
    version='0.3',
    url='',
    license='GPLv2',
    author='Jari Turkia',
    author_email='jatu@hqcodeshop.fi',
    description='Tool to get CIDRs of a known spammer IP-address by AS-number',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: System Administrators',

        # Specify the Python versions you support here.
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],
    python_requires='>=3.5, <4',
    install_requires=['ipwhois', 'netaddr'],
    scripts=['cert-check.py'],
    packages=find_packages()
)
