#!/usr/bin/env python3
from setuptools import setup, find_namespace_packages

setup(name="smurfnet"
        ,version="0.7.1"
        ,description="Client server model for using smurf on a network."
        ,author="Thomas Rometsch"
        ,package_dir={'': 'src'}
        ,packages=find_namespace_packages(where="src")
        ,install_requires=["diskcache", "pyyaml"]
        ,entry_points = {
                'console_scripts': ['smurfnet=smurfnet._command_line_:main',
                "smurfnet-shell=smurfnet.shell:main"],
        },
        zip_safe=True
        )
