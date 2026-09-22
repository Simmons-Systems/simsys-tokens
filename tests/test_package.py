from importlib.metadata import version

import simsys_tokens


def test_package_exposes_version():
    # Compared against the installed distribution rather than a literal, so a
    # version bump does not leave a stale assertion behind.
    assert simsys_tokens.__version__ == version("simsys-tokens")
