"""
ToolKit - Cloud-based Cybersecurity Products Implementation Solutions
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="toolkit-cybersec",
    version="1.0.0",
    author="ToolKit Team",
    description="Cloud-based cybersecurity products implementation solutions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/imharshitaa/toolkit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "boto3>=1.26.0",
        "requests>=2.28.0",
        "pyyaml>=6.0",
        "jinja2>=3.0.0",
        "docker>=6.0.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "toolkit=toolkit.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
