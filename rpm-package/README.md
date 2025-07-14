# Packaging RPM
There are two separate packages.

## Package 1: Python-code

### Prep
1. `ln -s rpm-package/rpm.json .`
2. `python -m venv venv.rpmvenv`
3. `. venv.rpmvenv/bin/activate`
4. `pip install rpmvenv`
5. `pip install rpmvenv-macros`
6. `pip install setuptools`
7. Install dependency libraries:
    *     dnf install cairo-devel gobject-introspection-devel \
            cairo-gobject-devel dbus-devel
8. Prep done!

### Package
1. Run this in package root directory, see previously run: `ln -s rpm-package/rpm.json .`
2. `rpmvenv rpm.json --verbose`
3. Wait for brand new `.rpm` to appear.
4. Done! `rpm --install` the resulting package.

### Python-wrappers
As running Python-code from dedicated venv is tricky, there are
`/usr/bin/spammer-block` and `/usr/bin/spammer-reporter` wrappers passing
through any/all arguments given.

## Package 2: SElinux-policy
Producing RPM from SElinux-policy is done traditionally.

### Prep
1. Install dependency libraries:
    *     dnf install rpm-build selinux-policy-devel
2. Make sure package _make_ is installed
3. Make sure your `rpmbuild/` directory tree exists

### Package
1. In `systemd.service/SElinux/` run `make`.
2. Make outputs a binary policy file `spammer-block_policy.pp`
3. Copy `spammer-block_policy.pp` and `spammer-block_policy.if` to your `rpmbuild/SOURCES/`
4. (working directory isn't a parameter) `rpmbuild -ba systemd.service/SElinux/spammer-block_policy_selinux.spec`
5. Resulting RPM will be stored into `rpmbuild/RPMS/noarch/`
6. Done! `rpm --install` the resulting package.

# Links

* https://github.com/kevinconway/rpmvenv
* https://github.com/danfoster/rpmvenv-macros
* [venv — Creation of virtual environments](https://docs.python.org/3/library/venv.html)
