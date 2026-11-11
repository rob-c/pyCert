"""pyCertWiz - a certificate manager for the UK e-Science CA (and ACME CAs).

Replaces the Java CertWizard tool and extends it into a manager for many user
and host certificates: request, wait for RA approval and CA signing, download
the issued certificate with its full chain, export encrypted PKCS#12 bundles,
deploy PEM files to services, monitor expiry and renew.

The public entry points are the ``pycert`` command line tool and the Qt GUI
(``pycert gui``).  The library modules are importable and documented; the
orchestration lives in :mod:`pycert.workflow` and CA protocols live behind the
provider interface in :mod:`pycert.providers`.
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
