![Tests](https://github.com/7RedViolin/pySigma-backend-cortexxdr/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/7RedViolin/18755c1cbd3b77ad90ce5da485b5bdcd/raw/7RedViolin-pySigma-backend-cortexxdr.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma CortexXDR Backend

This is the CortexXDR backend for pySigma. It provides the package `sigma.backends.cortexxdr` with the `CortexXDRBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.cortexxdr` for field renames and error handling. This pipeline is automatically applied to `SigmaRule` and `SigmaCollection` objects passed to the SentinelOneBackend class.

It supports the following output formats:

* default: plain CortexXDR XQL queries
* json: JSON-formatted CortexXDR XQL queries

This backend is currently maintained by:

* [Cori Smith](https://github.com/7RedViolin/)

## Installation
This can be installed via pip from PyPI or using pySigma's plugin functionality

### PyPI
```bash
pip install pysigma-backend-cortexxdr
```

### pySigma
```python
from sigma.plugins import SigmaPluginDirectory
plugins = SigmaPluginDirectory.default_plugin_directory()
plugins.get_plugin_by_id("cortexxdr").install()
```

## Usage

### sigma-cli
```bash
sigma convert -t cortexxdr proc_creation_win_office_onenote_susp_child_processes.yml
```

### pySigma
```python
from sigma.backends.cortexxdr import CortexXDRBackend
from sigma.rule import SigmaRule

rule = SigmaRule.from_yaml("""
title: Invoke-Mimikatz CommandLine
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: Invoke-Mimikatz
    condition: sel""")


backend = CortexXDRBackend()
print(backend.convert_rule(rule)[0])
```

## Side Notes & Limitations
- Backend uses XQL syntax
- Pipeline uses XQL field names
- Pipeline supports `linux`, `windows`, and `macos` product types
- Pipeline supports the following category types for field mappings
  - `process_creation`
  - `file_event`
  - `file_change`
  - `file_rename`
  - `file_delete`
  - `image_load`
  - `registry_add`
  - `registry_delete`
  - `registry_event`
  - `registry_set`
  - `network_connection`
  - `firewall`
- Any unsupported fields or categories will throw errors
