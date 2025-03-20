from setuptools import setup, find_packages

setup(
    name="fiptool",
    version="0.1.2",
    author="Oleg Primachenko",
    author_email="primachenko_oleg@outlook.com",
    description="A tool for working with FIP files",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/primachenko/fiptool",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'fiptool=fiptool.core:main',
        ],
    },
    include_package_data=True,
)
