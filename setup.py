from setuptools import setup, find_packages

setup(
    name="frece",
    version="1.0",
    description="FRECE - File Recovery Console Tool",
    author="Nakum-hub",
    packages=find_packages(),  # Automatically finds packages in your directory
    py_modules=["frece"],  # Specifies standalone Python modules
    entry_points={
        "console_scripts": [
            "frece=frece:main",  # Maps the command 'frece' to frece.main()
        ],
    },
    install_requires=[],  # Add dependencies if needed (e.g., ['requests'])
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
