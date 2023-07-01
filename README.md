![Tests](https://github.com/7RedViolin/pySigma-backend-cortexxdr/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/18755c1cbd3b77ad90ce5da485b5bdcd/raw/7RedViolin-pySigma-backend-cortexxdr.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma CortexXDR Backend

This is the CortexXDR backend for pySigma. It provides the package `sigma.backends.cortexxdr` with the `CortexXDRBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.cortexxdr`:

* CortexXDR: Uses the XQL query syntax

It supports the following output formats:

* default: plain CortexXDR XQL queries
* json: JSON-formatted CortexXDR XQL queries

This backend is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)