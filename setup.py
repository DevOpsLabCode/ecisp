#!/usr/bin/env python
import os
from setuptools import setup, find_packages

NAME = "enterprise-cloud-discovery-engine"
PACKAGE = "EnterpriseCloudDiscovery"
ROOT = os.path.dirname(__file__)
VERSION = __import__(PACKAGE).__version__

with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name=NAME,
    version=VERSION,
    description="Multi-cloud discovery and configuration evidence engine for the Enterprise Cloud Security Platform",
    long_description_content_type="text/markdown",
    long_description=open("README.md", encoding="utf-8").read(),
    author="DevOps Lab Inc.",
    author_email="hello@devopslabinc.com",
    url="https://devopslabinc.com",
    entry_points={"console_scripts": [
        "enterprise-cloud-discovery=EnterpriseCloudDiscovery.__main__:run_from_cli",
    ]},
    packages=find_packages(),
    package_data={
        "EnterpriseCloudDiscovery.data": ["*.json"],
        "EnterpriseCloudDiscovery.output": ["*.html", "*.js", "*.css", "*.zip"],
        "EnterpriseCloudDiscovery.providers": ["*.json"],
    },
    include_package_data=True,
    install_requires=requirements,
    license="Proprietary",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Private :: Do Not Upload",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
