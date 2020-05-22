from setuptools import (
        setup,
        find_packages,
)

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
        name='cryptopals',
        version='0.0.1',
        author='Max Wolfe',
        author_email='max@securitywolfe.com',
        description='Solutions for crytopals challenges',
        long_description=long_description,
        long_description_content_type='text/markdown',
        url='https://github.com/maxwolfe/cryptopals',
        packages=find_packages('cryptopals'),
        include_package_data=True,
        classifiers=[
            'Programming Language :: Python :: 3',
            'License :: OSI Approved :: MIT License',
            'Operating System :: OS Independent',
        ],
        python_requires='>=3.6',
)
