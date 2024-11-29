from setuptools import setup, find_packages

setup(
    name="frece",
    version="1.0",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'frece = frece:main',  # This assumes your script's main function is `main()`
        ],
    },
    install_requires=[
        'colorama',  # Any dependencies your tool needs
    ],
)
