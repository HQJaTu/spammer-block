import os
import toml


class ConfigReader:
    DEFAULT_FROM_ADDRESS = "joe.user@example.com"
    DEFAULT_SMTPD_ADDRESS = "127.0.0.1"
    DEFAULT_SYSTEMD_WATCHDOG_TIME = 5
    DEFAULT_LOG_LEVEL = "WARNING"

    @staticmethod
    def empty_config() -> dict:
        return {
            'Reporter': {
                'from_address': ConfigReader.DEFAULT_FROM_ADDRESS,
                'smtpd_address': ConfigReader.DEFAULT_SMTPD_ADDRESS,
                'spamcop_report_address': None,
                'mock_report_address': None,
            },
            'Daemon': {
                'watchdog_time': ConfigReader.DEFAULT_SYSTEMD_WATCHDOG_TIME,
                'maildir_base': None,
                'log_level': ConfigReader.DEFAULT_LOG_LEVEL,
                'force_root_override': False
            }
        }

    @staticmethod
    def config_from_toml_file(filename: str) -> dict:
        """
        Read configuration file.
        Note: Values from config can be missing or overwritten via command-line arguments.
        :param filename:
        :return: dictionary of configuration
        """
        toml_path = os.path.abspath(filename)
        with open(toml_path, "r", encoding="utf-8") as f:
            toml_string = f.read()
        parsed_toml = toml.loads(toml_string)

        # Sanity:
        known_keys = ConfigReader.empty_config()
        for key in parsed_toml:
            if key not in known_keys:
                raise ValueError("Unknown key '{}' in Toml-file {}!".format(key, filename))
            for subkey in parsed_toml[key]:
                if subkey not in known_keys[key]:
                    raise ValueError("Unknown key '{}.{}' in Toml-file {}!".format(key, subkey, filename))

        # Add directory of .toml file
        toml_dir = os.path.dirname(toml_path)
        parsed_toml["toml_dir"] = toml_dir

        # Merge empty config with parsed config.
        # NOTE: This won't work!
        # See: https://stackoverflow.com/a/26853961/1548275
        # config_out = {**known_keys, **parsed_toml}
        # Will merge subkey incorrectly. Need to walk the entire tree.
        config_out = {}
        for key in known_keys:
            config_out[key] = {}
            for subkey in known_keys[key]:
                if subkey in parsed_toml[key]:
                    config_out[key][subkey] = parsed_toml[key][subkey]
                else:
                    config_out[key][subkey] = known_keys[key][subkey]

        return config_out
