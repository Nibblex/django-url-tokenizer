import os
import setuptools

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setuptools.setup(
    name="django-url-tokenizer",
    version="0.0.12",
    author="Sergio Rodríguez",
    author_email="srodriguez3441@gmail.com",
    description="""A python package that provides a Django app that allows you to
    generate tokenized urls and send them to users via email.""",
    url="https://github.com/nibblex/django-url-tokenizer",
    packages=setuptools.find_packages(),
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "Django>=1.11",
    ],
)
