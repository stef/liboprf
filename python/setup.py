#!/usr/bin/env python

# SPDX-FileCopyrightText: 2023, Marsiske Stefan 
# SPDX-License-Identifier: LGPL-3.0-or-later

import os
from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name = 'pyoprf',
       version = '0.6.1',
       description = 'python bindings for liboprf',
       license = "LGPLv3",
       author = 'Stefan Marsiske',
       author_email = 'toprf@ctrlc.hu',
       url = 'https://github.com/stef/liboprf/python',
       long_description=read('README.md'),
       long_description_content_type="text/markdown",
       packages=find_packages(),
       install_requires = ("pysodium", "SecureString"),
       classifiers = ["Development Status :: 4 - Beta",
                      "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
                      "Topic :: Security :: Cryptography",
                      "Topic :: Security",
                   ],
       #ext_modules = [liboprf],
)
