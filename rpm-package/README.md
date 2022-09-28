# Packaging RPM

1. `ln -s rpm-package/rpm.json .`
2. `python -m venv venv.rpmvenv`
3. `. venv.rpmvenv/bin/activate`
4. `pip install rpmvenv`
5. `pip install rpmvenv-macros`
6. `rpmvenv rpm.json`
7. Wait for brand new `.rpm` to appear. Done! `rpm --install`

## Python-wrappers
As running Python-code from dedicated venv is tricky, there are
`/usr/bin/spammer-block` and `/usr/bin/spammer-reporter` wrappers passing
through any/all arguments given.

## Links

* https://github.com/kevinconway/rpmvenv
* https://github.com/danfoster/rpmvenv-macros
* [venv — Creation of virtual environments](https://docs.python.org/3/library/venv.html)
