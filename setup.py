from setuptools import setup  # type: ignore

setup(
    name="kaprien",
    version="0.1",
    py_modules=["cli"],
    install_requires=[
        "rich-click",
    ],
    entry_points="""
        [console_scripts]
        kaprien=kaprien:kaprien
    """,
)
