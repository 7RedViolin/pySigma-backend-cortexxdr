from .cortexxdr import CortexXDRBackend
from importlib.metadata import version, PackageNotFoundError

backends = {        # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "cortexxdr": CortexXDRBackend,
}

try:
    __version__ = version("pySigma-backend-cortexxdr")
except PackageNotFoundError:
    # package is not installed
    __version__ = "0.0.0"