# SPDX-License-Identifier: GPL-2.0

"""
Shared configuration-file parsing for the spammer-block tools.

configargparse's stock ``TomlConfigParser`` treats its section list as a
*fallback chain*: it reads the first listed section that has any content and
then stops, so ``['common', 'tool']`` never merges -- a non-empty ``[common]``
hides ``[tool]`` entirely.

``MergingTomlConfigParser`` instead reads *all* listed sections in order and
merges them, with later sections overriding earlier ones. That gives the
expected "``[common]`` base + ``[tool]`` overrides" behaviour.

Pair it with ``ignore_unknown_config_file_keys=True`` on the ArgumentParser so a
shared key (e.g. ``asn-database`` in ``[common]``) is simply ignored by a tool
that doesn't define it, instead of aborting with "unrecognized arguments".
"""

import configargparse
from collections import OrderedDict


class MergingTomlConfigParser(configargparse.TomlConfigParser):
    """
    TOML config parser that merges all listed sections instead of stopping
    at the first non-empty one.
    """

    def parse(self, stream):
        """
        Parse a TOML stream, merging every configured section in order.
        :param stream: open config file stream.
        :return: OrderedDict of merged key -> value (values stringified, lists kept).
        """
        import toml
        try:
            config = toml.load(stream)
        except Exception as exc:
            raise configargparse.ConfigFileParserException(
                "Couldn't parse TOML file: %s" % exc)

        result = OrderedDict()
        for section in self.sections:
            data = configargparse.get_toml_section(config, section)
            if not data:
                continue
            for key, value in data.items():
                if isinstance(value, list):
                    result[key] = value
                elif value is None:
                    continue
                else:
                    # Values are stringified; argparse converts them back via
                    # each argument's type/action.
                    result[key] = str(value)

        return result
