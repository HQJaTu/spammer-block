from setuptools import setup, find_packages

setup(
    name='spammer-block',
    version='0.7',
    url='https://github.com/HQJaTu/spammer-block',
    license='GPLv2',
    author='Jari Turkia',
    author_email='jatu@hqcodeshop.fi',
    description='Tool to get CIDRs of a known spammer IP-address by AS-number and report known spam automatically',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: System Administrators',

        # Specify the Python versions you support here.
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
        'Programming Language :: Python :: 3.10'
    ],
    python_requires='>=3.8, <4',
    install_requires=['ipwhois @ git+https://github.com/HQJaTu/ipwhois.git@ipinfo.io',
                      'netaddr==0.8.0',
                      'requests==2.27.1',
                      'asyncio-glib==0.1',
                      'asyncinotify==2.0.2',
                      'systemd-watchdog==0.9.0',
                      'dbus-python==1.2.18',
                      'toml==0.10.2'
                      ],
    scripts=['cli-utils/spammer-block.py',
             'cli-utils/spammer-reporter.py',
             'cli-utils/spammer-reporter-service.py'],
    packages=find_packages()
)
