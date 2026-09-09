import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setuptools.setup(
    name="cde_shared_lib",
    version="4.0.0",
    author="Cyber Data Engine",
    author_email="admin@cyberdataengine.local",
    description="Standalone Core Library for Cyber Data Engine - RAG and Parsing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cyber-data-engine",
    packages=["shared_lib"],
    install_requires=[
        "pydantic>=2.0.0",
        "pypdf>=4.0.0",
        "python-docx>=1.0.0",
        "openpyxl>=3.1.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.9",
)
