# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import os
import pathlib
import sys

# Make your package importable
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))  # <- make src/ importable
# repo root so "import src.client" works
sys.path.insert(0, os.path.abspath(".."))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "TLS line protocol"
copyright = "2025, Elliott Bache"
author = "Elliott Bache"
release = "0.0.1"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.doctest",
    "sphinx.ext.napoleon",
    "breathe",
    "sphinxcontrib.mermaid",  # the mermaid extension
]
source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
myst_heading_anchors = 3  # create anchors for ##, ###, etc.

# Generate autosummary stub pages automatically on build
autosummary_generate = True

# Ensure module pages include their members (functions, classes, etc.)
autodoc_default_options = {
    "members": True,
    "undoc-members": True,  # optional
    "show-inheritance": True,  # harmless if you have no classes
    # "imported-members": True,  # enable if you re-export from other modules
}

# If you use Google/NumPy docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]


# add C++ documentation
# Sphinx (docs/conf.py)
breathe_default_project = "tls-line-protocol"

DOCS = pathlib.Path(__file__).parent
BREATHE_XML = DOCS / "_build" / "doxygen" / "xml"
breathe_projects = {"tls-line-protocol": str(BREATHE_XML)}
