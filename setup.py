#!/usr/bin/env python3
from setuptools import setup, find_namespace_packages

setup(name="simdata-net"
        ,version="0.5"
        ,description="Client server model for using simdata on a network."
        ,author="Thomas Rometsch"
        ,package_dir={'': 'src'}
        ,packages=find_namespace_packages(where="src")
        ,install_requires=["simdata", "diskcache"]
        ,entry_points = {
                'console_scripts': ['simdata-net=simdata_net._command_line_:main'],
        },
        zip_safe=True
        )
