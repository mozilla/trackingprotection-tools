from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()
with open("README.md", "r") as f:
    long_description = f.read()

setup(
    # Meta
    author='Mozilla Corporation',
    author_email='senglehardt@mozilla.com',
    description='Tools for working with Firefox Tracking Protection.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    name='trackingprotection-tools',
    license='MPL 2.0',
    url='https://github.com/mozilla/trackingprotection-tools',
    version='0.4.1',
    packages=['trackingprotection_tools'],

    # Dependencies
    install_requires=requirements,
    setup_requires=['setuptools_scm'],

    # Packaging
    include_package_data=True,
    use_scm_version=False,
    zip_safe=False,

    # Classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment :: Mozilla',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Scientific/Engineering :: Information Analysis'
    ],
)
