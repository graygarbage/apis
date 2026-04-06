from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cohesity-iam-scoper",
    version="1.0.0",
    author="Cohesity",
    description="CLI tool to generate least-privilege IAM policies for Cohesity Cloud Edition in AWS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "cohesity_iam_scoper": [],
        "": ["data/**/*.json"],
    },
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cohesity-iam-scoper=cohesity_iam_scoper.cli:cli",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
)
