import pytest
import re
from pathlib import Path
from python_freeipa.client_meta import ClientMeta
from shutil import copyfile
from subprocess import check_output

from SCAutolib import TEMPLATES_DIR
from SCAutolib.models import local_ca, ipa_server


@pytest.fixture()
def dummy_ipa_vals(ipa_ip, ipa_hostname, ipa_admin_passwd, ipa_root_passwd):
    """
    Creates dummy values for IPA serve and client for testings
    """
    domain = ipa_hostname.split(".", 1)[1]
    return {
        "server_ip": ipa_ip,
        "server_domain": domain,
        "server_hostname": ipa_hostname,
        "server_admin_passwd": ipa_admin_passwd,
        "server_realm": domain.upper(),
        "server_root_passwd": ipa_root_passwd,
        "client_hostname": f"client-hostname.{domain}"
    }


@pytest.fixture()
def ipa_meta_client(dummy_ipa_vals):
    """
    Return ready-to-use IPA MetaClient with admin login. This fixture might not
    work if there is no mapping rule on your system for given IPA IP address and
    IPA hostnames (no corresponding entry in /etc/hosts)
    """
    client = ClientMeta(dummy_ipa_vals["server_hostname"], verify_ssl=False)
    client.login("admin", dummy_ipa_vals["server_admin_passwd"])
    return client


@pytest.fixture()
def clean_ipa():
    yield
    check_output(["ipa-client-install", "--uninstall", "--unattended"],
                 encoding="utf-8")


def test_local_ca_setup(backup_sssd_ca_db, tmpdir, caplog):
    sssd_auth_ca_db = Path("/etc/sssd/pki/sssd_auth_ca_db.pem")
    ca = local_ca.LocalCA(Path(tmpdir, "ca"))
    ca.setup()

    assert ca.root_dir.exists()
    assert ca._ca_cert.exists()
    assert ca._ca_key.exists()
    assert ca._ca_key.exists()

    with ca._ca_cert.open("r") as f:
        # This directory has to be created by the LocalCA.setup()
        with sssd_auth_ca_db.open()as f_db:
            assert f.read() in f_db.read()

    assert "Local CA is configured" in caplog.messages


@pytest.mark.parametrize("force", (False, True))
def test_local_ca_setup_force(backup_sssd_ca_db, tmpdir, caplog, force):
    tmp_file = Path(tmpdir, "ca", "some-file")
    tmp_file.parent.mkdir()
    tmp_file.touch()

    assert tmp_file.exists()

    ca = local_ca.LocalCA(Path(tmpdir, "ca"))
    ca.setup(force=force)

    if force:
        assert not tmp_file.exists()
        assert "Removing configuration." in caplog.messages
    else:
        assert tmp_file.exists()
        assert "Skipping configuration." in caplog.messages


def test_request_cert(local_ca_fixture, tmpdir):
    csr = Path(tmpdir, "username.csr")
    cnf = Path(tmpdir, "user.cnf")
    copyfile(Path(TEMPLATES_DIR, "user.cnf"), Path(tmpdir, cnf))

    with cnf.open("r+") as f:
        f.write(f.read().format(user="username"))

    cmd = ['openssl', 'req', '-new', '-days', '365', '-nodes', '-newkey',
           'rsa:2048', '-keyout', f'{tmpdir}/username.key', '-out', csr,
           "-reqexts", "req_exts", "-config", cnf]
    check_output(cmd, encoding="utf-8")

    cert = local_ca_fixture.request_cert(csr, "username")
    assert cert.exists()


def test_revoke_cert(local_ca_fixture, tmpdir):
    csr = Path(tmpdir, "username.csr")
    cnf = Path(tmpdir, "user.cnf")
    copyfile(Path(TEMPLATES_DIR, "user.cnf"), Path(tmpdir, cnf))
    username = "username"
    with cnf.open("r+") as f:
        f.write(f.read().format(user=username))
    cmd = ['openssl', 'req', '-new', '-days', '365', '-nodes', '-newkey',
           'rsa:2048', '-keyout', f'{tmpdir}/{username}.key', '-out', csr,
           "-reqexts", "req_exts", "-config", cnf]
    check_output(cmd, encoding="utf-8")

    cert = local_ca_fixture.request_cert(csr, username)
    local_ca_fixture.revoke_cert(cert)

    with local_ca_fixture._serial.open("r") as f:
        index = int(f.read()) - 1

    rex = re.compile(
        fr"^R\s+[0-9A-Z]+\s+[0-9A-Z]+\s+.*{index}\s+.*/CN={username}\n$")

    with open(Path(local_ca_fixture.root_dir, "index.txt"), "r") as f:
        assert re.match(rex, f.read())


def test_ipa_server_simple_setup(ipa_meta_client, dummy_ipa_vals, clean_ipa,
                                 caplog):
    ipa_ca = ipa_server.IPAServerCA(ip_addr=dummy_ipa_vals["server_ip"],
                                    client_hostname=dummy_ipa_vals[
                                        "client_hostname"],
                                    hostname=dummy_ipa_vals["server_hostname"],
                                    root_passwd=dummy_ipa_vals[
                                        "server_root_passwd"],
                                    admin_passwd=dummy_ipa_vals[
                                        "server_admin_passwd"],
                                    domain=dummy_ipa_vals["server_domain"])

    ipa_ca.setup()

    # Test if meta client can get info about freshly configured host
    ipa_meta_client.host_show(a_fqdn=dummy_ipa_vals["client_hostname"])

    # Cleanup after test
    ipa_meta_client.host_del(a_fqdn=dummy_ipa_vals["client_hostname"])
