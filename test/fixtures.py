import pytest
from SCAutolib import models


@pytest.fixture(scope="session")
def local_ca_fixture(tmp_path_factory):
    ca = models.local_ca.LocalCA(tmp_path_factory.mktemp("local-ca"))
    ca.setup(force=True)
    return ca
