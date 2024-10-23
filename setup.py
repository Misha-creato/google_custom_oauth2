from setuptools import setup, find_packages


with open('requirements.txt') as f:
    requirements = f.read().splitlines()


setup(
    name="google_custom_oauth2",
    version="0.1.0",
    summary="Google oauth2 authorization library",
    author="Rina",
    author_email="oparina.iri@gmail.com",
    url="https://github.com/Misha-creato/google_custom_oauth2",
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=requirements,
)
