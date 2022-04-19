from shutil import copyfile

import pytest
from SCAutolib import models
from pathlib import Path


@pytest.fixture(scope="session")
def backup_sssd_ca_db(tmp_path_factory):
    backup = None
    sssd_auth_ca_db = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")
    if sssd_auth_ca_db.exists():
        # Save SSSD CA db
        backup = tmp_path_factory.mktemp("backup").joinpath(
            "sssd_auth_ca_db.pem")
        copyfile(sssd_auth_ca_db, backup)

    yield

    # Restore SSSD CA db
    if backup:
        copyfile(backup, "/etc/sssd/pki/sssd_auth_ca_db.pem")
    else:
        sssd_auth_ca_db.unlink()


@pytest.fixture(scope="session")
def local_ca_fixture(tmp_path_factory, backup_sssd_ca_db):
    ca = models.local_ca.LocalCA(tmp_path_factory.mktemp("local-ca"))
    ca.setup(force=True)
    return ca
