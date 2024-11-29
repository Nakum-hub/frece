from setuptools import setup, find_packages

setup(
    name="frece",
    version="1.0",
    description="FRECE - File Recovery Console Tool",
    author="Nakum-hub",
    packages=find_packages(),  # Automatically finds all packages in your directory
    py_modules=["frece"],  # Specifies standalone Python modules if the main script is frece.py
    entry_points={
        "console_scripts": [
            "frece=frece:main",  # Maps 'frece' command to the `main()` function in frece.py
        ],
    },
    install_requires=[
        "colorama>=0.4.4",  # Add required dependencies with versions
        "pyreadline; platform_system=='Windows'",  # Conditional dependency for Windows
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Environment :: Console",
        "Topic :: System :: Filesystems",
        "Topic :: Utilities",
    ],
    python_requires=">=3.6",  # Ensures compatibility with Python 3.6+
)
