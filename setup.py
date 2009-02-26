from setuptools import setup, find_packages

setup(
    name='django_oauth_consumer',
    version='0.0.1',
    description='OAuth Consumer Application for Django',
    author='Naitik Shah',
    author_email='n@daaku.org',
    url='https://code.daaku.org/django-oauth-consumer/',
    packages=find_packages(),
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    include_package_data=True,
    zip_safe=False,
    install_requires=['setuptools', 'setuptools_git', 'django', 'oauth', 'make_request', 'urlencoding'],
)
