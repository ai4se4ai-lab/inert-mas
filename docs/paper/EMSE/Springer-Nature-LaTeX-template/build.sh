#!/usr/bin/env bash
# Build the manuscript (single main.tex + single sn-bibliography.bib).
set -e
cd "$(dirname "$0")"
export BSTINPUTS=bst:
pdflatex -interaction=nonstopmode main.tex > /dev/null || true
bibtex main
pdflatex -interaction=nonstopmode main.tex > /dev/null || true
pdflatex -interaction=nonstopmode main.tex | grep -E "^!|undefined|Output written" || true
