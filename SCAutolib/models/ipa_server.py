import os
from hashlib import md5
from pathlib import Path
from socket import gethostname

import paramiko
from SCAutolib import logger
from SCAutolib import run, LIB_DIR
from SCAutolib.exceptions import SCAutolibException
from SCAutolib.models.ca import CA
# from SCAutolib.models.sssd_conf import SSSDConf
# from SCAutolib.models.user import IPAUser
from cryptography import x509
from fabric.connection import Connection
from invoke import Responder
from python_freeipa.client_meta import ClientMeta
from python_freeipa import exceptions


class IPAServerCA(CA):
    """
    Some documentation about IPAServer CA
    """
    _ipa_server_ip: str = None
    _ipa_server_hostname: str = None
    _ipa_server_domain: str = None
    _ipa_server_admin_passwd: str = None
    _ipa_server_realm: str = None
    _ipa_client_hostname: str = None
    _ipa_server_root_passwd: str = None
    meta_client: ClientMeta = None

    def __init__(self, ip_addr: str, hostname: str, domain: str,
                 admin_passwd: str, root_passwd: str, client_hostname: str,
                 realm: str = None):
        """
        Initialize object for IPA client for given IPA server. Also, creates
        meta client (python_freeipa.client_meta.ClientMeta) logged in to the
        server and ready-to-use.

        :param ip_addr: IP address of the IPA server
        :param hostname: Hostname of the IPA server
        :param domain: Domain name of the IPA server
        :param admin_passwd: Password for admin user on the IPA server
        :param root_passwd: Password for root user on the IPA server
                            (system user)
        :param client_hostname: Hostname for the client. This name would be set
                                on the client host
        :param realm: Kerberos realm. If not set, domain in upper cases would
                      be used instead
        """

        self._ipa_server_ip = ip_addr
        self._ipa_server_domain = domain
        self._ipa_server_hostname = hostname
        self._ipa_server_admin_passwd = admin_passwd
        self._ipa_server_realm = realm if realm is not None else domain.upper()
        self._ipa_client_hostname = client_hostname
        self._ipa_server_root_passwd = root_passwd
        self.meta_client: ClientMeta = ClientMeta(self._ipa_server_hostname,
                                                  verify_ssl=False)
        self.meta_client.login("admin", self._ipa_server_admin_passwd)

    def setup(self, force: bool = False):
        """
        Setup IPA client for IPA server. After IPA client is installed, system
        would be configured for smart card login with IPA using script from
        IPA server obtained via SSH.

        :param force: if True, previous installation of the IPA client would be
            removed
        :type force: bool
        """

        if self.is_installed:
            logger.info("IPA client is already configured on the system.")
            if not force:
                logger.info("Set force argument to True if you want to remove"
                            "previous installation.")
                return
            self.restore()

        logger.info(f"Start setup of IPA client on the system for "
                    f"{self._ipa_server_hostname} IPA server.")

        self._add_to_hosts()
        self._add_to_resolv()
        self._set_hostname()

        run(["ipa-client-install", "-p", "admin",
             "--password", self._ipa_server_admin_passwd,
             "--server", self._ipa_server_hostname,
             "--domain", self._ipa_server_domain,
             "--realm", self._ipa_server_realm,
             "--hostname", self._ipa_client_hostname,
             "--all-ip-addresses", "--force", "--force-join", "--no-ntp", "-U"],
            input="yes")
        logger.debug("IPA client is installed")

        # SSSDConf.set(key="certificate_verification", value="no_ocsp",
        #              section="sssd")
        # FIXME: restart service with internal call
        # run("systemctl restart sssd")

        ipa_client_script = self._get_sc_setup_script()
        run(f'bash {ipa_client_script} /etc/ipa/ca.crt')
        logger.debug("Setup of IPA client for smart card is finished")

        policy = self.meta_client.pwpolicy_show(a_cn="global_policy")["result"]
        if "0" not in policy["krbminpwdlife"]:
            self.meta_client.pwpolicy_mod(a_cn="global_policy", o_krbminpwdlife=0)
            logger.debug("Minimal kerberos password lifetime is set to 0 days")
        if "365" not in policy["krbmaxpwdlife"]:
            self.meta_client.pwpolicy_mod(a_cn="global_policy", o_krbmaxpwdlife=365)
            logger.debug("Maximum kerberos password lifetime is set to 365 days")

        # TODO: add to restore client host name
        logger.info("IPA client is configured on the system.")

    @property
    def is_installed(self):
        """
        :return: True, if IPA client is installed on the system (ipa command
            returns zero return code), otherwise False
        :rtype: bool
        """
        out = run(["ipa"], print_=False)
        return out.returncode == 0

    def _set_hostname(self):
        """
        Set hostname for specified IPA client hostname
        """
        run(f"hostnamectl set-hostname {self._ipa_client_hostname} --static")
        logger.debug(f"Hostname is set to {self._ipa_client_hostname}")

    def _add_to_resolv(self):
        """
        Add new nameserver (IPA) to /etc/resolv.conf and lock this file for
        editing
        """
        nameserver = f"nameserver {self._ipa_server_ip}"
        with open("/etc/resolv.conf", "w+") as f:
            cnt = f.read()
            if nameserver not in cnt:
                logger.warning(f"Nameserver {self._ipa_server_ip} is not "
                               "present in /etc/resolve.conf. Adding...")
                f.write(nameserver + "\n" + cnt)
                logger.info(
                    "IPA server is added to /etc/resolv.conf "
                    "as first nameserver")
                run("chattr -i /etc/resolv.conf")
                logger.info("File /etc/resolv.conf is blocked for editing")

    def _add_to_hosts(self):
        """
        Add IPA server (IP address and hostname) to /etc/hosts
        """
        entry = f"{self._ipa_server_ip} {self._ipa_server_hostname}"
        with open("/etc/hosts", "r+") as f:
            cnt = f.read()
            if entry not in cnt:
                f.write(entry)
                logger.warning(
                    f"New entry {entry} for IPA server is added to /etc/hosts")
            logger.info(
                f"Entry for IPA server {entry} presents in the /etc/hosts")

    def _get_sc_setup_script(self) -> Path:
        """
        Fetch script for smart card setup of IPA client. Script is generated
        only on IPA server. Fetching is made by connecting to the host via SSH.

        :return: Path to script
        :rtype: patlib.Path
        """
        ipa_client_script = Path(LIB_DIR, "ipa-client-sc.sh")
        run("kinit admin", input=self._ipa_server_admin_passwd)
        logger.debug("Kerberos ticket for admin user is obtained")
        kinitpass = Responder(pattern="Password for admin@SC.TEST.COM: ",
                              response="SECret.123\n")
        with Connection(self._ipa_server_ip, user="root",
                        connect_kwargs={"password":
                                        self._ipa_server_root_passwd}) as c:
            # Delete this block when PR in paramiko will be accepted
            # https://github.com/paramiko/paramiko/issues/396
            #### noqa:E266
            paramiko.PKey.get_fingerprint = \
                self.__PKeyChild.get_fingerprint_improved
            c.client = paramiko.SSHClient()
            c.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            #### noqa:E266
            c.open()
            # in_stream = False is required because while testing with pytest
            # it collision appears with capturing of the output.
            c.run("kinit admin", pty=True, watchers=[kinitpass], in_stream=False)
            result = c.run("ipa-advise config-client-for-smart-card-auth",
                           hide=True, in_stream=False)
            with open(ipa_client_script, "w") as f:
                f.write(result.stdout)
        if os.stat(ipa_client_script).st_size == 0:
            msg = "Script for IPA client smart card setup is not correctly " \
                  "copied to the host"
            logger.error(result.stdout)
            logger.error(result.stderr)
            raise SCAutolibException(msg)
        logger.debug("File for setting up IPA client for smart cards is "
                     f"copied to {ipa_client_script}")
        return ipa_client_script

    def request_cert(self, csr: Path, username: str, cert_out: Path):
        """
        Request certificate using CSR from IPA CA for given username. It is
        a wrapper around the python_freeipa.client_meta.ClientMeta.cert_request
        method. It works with a file, extracts CSR data from it and then
        stores in PEM format adding required prefix and suffix as in normal
        certificate and. If cert_out is a directory, then certificate would be
        stored in this directory with name <username>.pem. If it is a file,
        then check if it has PEM extension. If not, append .pem suffix to the
        name.

        :param csr: path to CSR
        :type csr: patlib.Path
        :param username: subject for the certificate
        :type username: str
        :param cert_out: path where the certificate is stored. Can be a
                         directory or a file.
        :type cert_out: patlib.Path

        :return: Path to the PEM certificate.
        :rtype: patlib.Path
        """
        with csr.open() as f:
            csr_content = f.read()
        resp = self.meta_client.cert_request(a_csr=csr_content,
                                             o_principal=username)
        cert = resp["result"]["certificate"]

        if cert_out.is_dir():
            cert_out = cert_out.joinpath(f"{username}.pem")
        elif cert_out.is_file() and not cert_out.name.endswith(".pem"):
            cert_out.rename(cert_out.with_suffix(".pem"))

        with cert_out.open("w") as f:
            f.write("-----BEGIN CERTIFICATE-----\n"
                    f"{cert}\n"
                    f"-----END CERTIFICATE-----")
        return cert_out

    def add_user(self, user):
        """
        Add given user to IPA server. It is a wrapper on the
        python_freeipa.client_meta.ClientMeta.user_add method. Just extracts
        necessary fields from IPAUser objet and pass them to the method. As a
        result, o_givenname == o_uid == o_sn == o_cn for simplicity.

        :param user: User to be added to the IPA server.
        """
        r = self.meta_client.user_add(user.username, user.username,
                                      user.username, user.username,
                                      o_userpassword=user.password)
        logger.debug(r)
        logger.info(f"User {user.username} is added to the IPA server")

    def del_user(self, user):
        """
        Remove user from IPA server.
        :param user: User to be deleted

        :raise AssertionError: If operation is failed. Fail is detected in
            return value from request to IPA server.
        """
        r = self.meta_client.user_del(user.username)["result"]
        logger.debug(r)
        assert r["failed"] == []
        logger.info(f"User {user.username} is removed from the IPA server")

    def revoke_cert(self, cert_path: Path):
        """
        Revoke given certificate on the IPA server. It is a wrapper on the
        python_freeipa.client_meta.ClientMeta.revoke_cert method. It extracts
        serial number of the certificate from the file

        :param cert_path: Path to the certificate in PEM format

        """
        with cert_path.open("rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        resp = self.meta_client.cert_revoke(cert.serial_number)
        logger.debug(f"Response {resp}")
        logger.info(f"Certificate {cert.serial_number} is revoked")
        return cert.serial_number

    def restore(self):
        """
        Remove IPA client from the system and from the IPA server

        :raise subprocess.CalledProcessError: by run function
        """

        logger.warning("Removing IPA client from the host "
                       f"{gethostname()}")
        try:
            out = self.meta_client.host_del(
                a_fqdn=gethostname(), o_updatedns=True)["result"]
            assert out["failed"] == []
        except exceptions.NotFound:
            logger.error(f"Current hostname ({gethostname()}) is not found "
                         f"on the IPA server")
        run(["ipa-client-install", "--uninstall", "-U"], check=True)
        logger.info("IPA client is removed.")

    class __PKeyChild(paramiko.PKey):
        """This child class is need to fix SSH connection with MD5 algorith
        in FIPS mode

        This is just workaround until PR in paramiko would be accepted
        https://github.com/paramiko/paramiko/issues/396. After this PR is merged,
        delete this class
        """

        def get_fingerprint_improved(self):
            return md5(self.asbytes(), usedforsecurity=False).digest()
