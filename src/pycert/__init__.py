"""pyCert - a dependency-light Python client for the UK e-Science CA.

Replaces the Java CertWizard tool: request a certificate, wait for RA approval
and CA signing, download the issued certificate with its full chain, and write
an encrypted PKCS#12 bundle with a saved secret.

The public entry points are the ``pycert`` command line tool and the Tkinter GUI
(``pycert gui``).  The library modules are importable and documented; the
orchestration lives in :mod:`pycert.workflow`.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
