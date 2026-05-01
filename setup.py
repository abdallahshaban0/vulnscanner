from setuptools import setup, find_packages
import os

# Read long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vulnscanner",
    version="1.0.0",
    author="Abdallah Shaban",
    description="Automated Vulnerability Scanner for Ethical Hacking & Penetration Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/abdallahshaban0/vulnscanner",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "vulnscanner=scanner:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Education",
        "Environment :: Console",
    ],
    keywords="security vulnerability scanner penetration testing ethical hacking",
)
