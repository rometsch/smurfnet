""" Config structure for smurf. """
import os
import sys
import yaml

home_path = os.path.join(os.path.expanduser("~"), ".smurfnet")

information_types = [
    "cache_dir",
    "key_dir",
    "relay"
]

def main(parser=None):
    if parser is None:
        import argparse
        parser = argparse.ArgumentParser()

    build_parser(parser)
    options = parser.parse_args()
    cli(options)

def cli(options):
    options.func(options)

def show_config(options):
    c = Config()
    c.print()

def print_value(options):
    c = Config()
    c.print_value(options.key)

def add_entry(options):
    c = Config()
    c.add(options.key, options.value)

def remove_entry(options):
    c = Config()
    c.remove(options.key, options.value)


def build_parser(parser=None):
    parser.set_defaults(func=show_config)

    subparsers = parser.add_subparsers(dest='subparser_name')
    parser_add = subparsers.add_parser('add', help='Add a config item.')
    parser_add.add_argument("key",
                            choices=information_types,
                            help="What to set.")
    parser_add.add_argument("value")
    parser_add.set_defaults(func=add_entry)

    parser_remove = subparsers.add_parser('remove',
                                          help='Remove a config item.')
    parser_remove.add_argument("key",
                               choices=information_types,
                               help="What to set.")
    parser_remove.add_argument("value")
    parser_remove.set_defaults(func=remove_entry)

    parser_show = subparsers.add_parser('show', help='Show the config.')
    parser_show.set_defaults(func=show_config)

    parser_get = subparsers.add_parser(
        'get', help='Return the value of a root level config item.')
    parser_get.add_argument("key", help="What to get.")
    parser_get.set_defaults(func=print_value)

def expand_path(path):
    abspath = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(abspath):
        raise FileNotFoundError("No such directory: {}".format(path))
    return abspath


def check_information_type(info_type):
    if not any((info_type == t for t in information_types)):
        raise AttributeError(
            "Information type {} not supported".format(info_type))


class Config:
    def __init__(self):
        if not os.path.exists(home_path):
            os.makedirs(home_path)
        self.config_file = os.path.join(home_path, "config.yaml")
        self.load()

    def add(self, what, val):
        check_information_type(what)
        if what == "rootdir":
            self.add_rootdir(val)
        elif what == "host":
            list_name = what + "_list"
            if not list_name in self.data:
                self.data[list_name] = []
            self.data[list_name].append(val)
        else:
            self.data[what] = val
        self.save()

    def remove(self, what, val):
        check_information_type(what)
        list_name = what + "_list"
        try:
            for n in range(len(self.data[list_name])):
                if self.data[list_name][n] == val:
                    del self.data[list_name][n]
                    break
            self.save()
        except KeyError:
            print("No config for type", what)
            pass

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, val):
        self.data[key] = val

    def save(self):
        self.data["type"] = "smurfnet config"
        self.data["version"] = "0.1"
        with open(self.config_file, "w") as outfile:
            yaml.dump(self.data, outfile)

    def load(self):
        try:
            with open(self.config_file, "r") as infile:
                self.data = yaml.safe_load(infile)
        except FileNotFoundError:
            self.data = {}
            self.data["host_list"] = []
            self.data["key_dir"] = os.path.join(home_path, "keys")

    def print(self):
        import pprint
        pprint.pprint(self.data)

    def print_value(self, key):
        try:
            print(self[key])
        except KeyError:
            print("Error: No config value found for key '{}'".format(key))
            sys.exit(1)


if __name__ == "__main__":
    main()
