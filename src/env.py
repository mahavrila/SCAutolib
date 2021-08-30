import pwd
from configparser import ConfigParser
from os import chmod, environb, remove
from os.path import split, exists
from pathlib import Path
from posixpath import join
from shutil import rmtree, copytree, copyfile
from subprocess import PIPE, Popen, CalledProcessError
import subprocess

import python_freeipa as pipa
from SCAutolib.src import *
from SCAutolib.src import utils, exceptions
from SCAutolib.src.exceptions import UnspecifiedParameter, SCAutolibException
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def create_cnf(user: str, conf_dir=None):
    """
    Create configuration files for OpenSSL to generate certificates and requests
    by local CA.

    Args:
        user: username for which CNF should be created. If user = ca, then cnf
              would be created for CA.
        conf_dir: directory where CNF file would be placed.
    """
    if user == "ca":
        ca_dir = read_config("ca_dir")
        conf_dir = join(ca_dir, "conf")
        
        ca_cnf = f"""[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = {ca_dir}
database         = $dir/index.txt
new_certs_dir    = $dir/newcerts

certificate      = $dir/rootCA.pem
serial           = $dir/serial
private_key      = $dir/rootCA.key
RANDFILE         = $dir/rand

default_days     = 365
default_crl_hours = 1
default_md       = sha256

policy           = policy_any
email_in_dn      = no

name_opt         = ca_default
cert_opt         = ca_default
copy_extensions  = copy

[ usr_cert ]
authorityKeyIdentifier = keyid, issuer

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ policy_any ]
organizationName       = supplied
organizationalUnitName = supplied
commonName             = supplied
emailAddress           = optional

[ req ]
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
O  = Example
OU = Example Test
CN = Example Test CA
"""

        with open(f"{conf_dir}/ca.cnf", "w") as f:
            f.write(ca_cnf)
            env_logger.debug(
                f"Configuration file for local CA is created {conf_dir}/ca.cnf")
        return

    user_cnf = f"""
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
O = Example
OU = Example Test
CN = {user}

[ req_exts ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "{user}"
subjectKeyIdentifier = hash
keyUsage = critical, nonRepudiation, digitalSignature
extendedKeyUsage = clientAuth, emailProtection, msSmartcardLogin
subjectAltName = otherName:msUPN;UTF8:{user}@EXAMPLE.COM, email:{user}@example.com
"""
    if conf_dir is None:
        raise exceptions.UnspecifiedParameter("conf_dir", "Directory with configurations is not provided")
    with open(f"{conf_dir}/req_{user}.cnf", "w") as f:
        f.write(user_cnf)
        env_logger.debug(f"Configuration file for CSR for user {user} is created "
                         f"{conf_dir}/req_{user}.cnf")


def create_sssd_config():
    """
    Update the content of the sssd.conf file. If file exists, it would be store
    to the backup folder and content in would be edited for testing purposes.
    If file doesn't exist, it would be created and filled with default options.
    """
    cnf = ConfigParser(allow_no_value=True)
    cnf.optionxform = str  # Needed for correct parsing of uppercase words
    default = {
        "sssd": {"#<[sssd]>": None,
                 "debug_level": "9",
                 "services": "nss, pam",
                 "domains": "shadowutils"},
        "nss": {"#<[nss]>": None,
                "debug_level": "9"},
        "pam": {"#<[pam]>": None,
                "debug_level": "9",
                "pam_cert_auth": "True"},
        "domain/shadowutils": {"#<[domain/shadowutils]>": None,
                               "debug_level": "9",
                               "id_provider": "files"},
    }

    # cnf.read_dict(default)

    sssd_conf = "/etc/sssd/sssd.conf"
    if exists(sssd_conf):
        bakcup_dir = utils.backup_(sssd_conf, name="sssd-original.conf")
        add_restore("file", sssd_conf, bakcup_dir)

    with open(sssd_conf, "r") as f:
        cnf.read_file(f)

    for key, value in default.items():
        cnf[key] = value

    with open(sssd_conf, "w") as f:
        cnf.write(f)
        env_logger.debug("Configuration file for SSSD is updated "
                         "in  /etc/sssd/sssd.conf")
    chmod(sssd_conf, 0o600)


def create_softhsm2_config(card_dir: str):
    """
    Create SoftHSM2 configuration file in conf_dir. Same directory has to be used
    in setup-ca function, otherwise configuration file wouldn't be found causing
    the error. conf_dir expected to be in work_dir.
    """
    conf_dir = f"{card_dir}/conf"

    with open(f"{conf_dir}/softhsm2.conf", "w") as f:
        f.write(f"directories.tokendir = {card_dir}/tokens/\n"
                f"slots.removable = true\n"
                f"objectstore.backend = file\n"
                f"log.level = INFO\n")
        env_logger.debug(f"Configuration file for SoftHSM2 is created "
                         f"in {conf_dir}/softhsm2.conf.")


def create_virt_card_service(username: str, card_dir: str):
    """Create systemd service for for virtual smart card. Service will have
    a name in form of virt_cacard_<username>.service where <username> would be
    replace with value specified by username parameter.
    Args:
         username: username of the user for the virtual smart card.
         card_dir: directory where all necessary item for virtual smart card
                   are located (need to specify path to softhsm2.conf file in
                   the service file).s
    """
    path = f"/etc/systemd/system/virt_cacard_{username}.service"
    conf_dir = f"{card_dir}/conf"
    default = {
        "Unit": {
            "Description": f"virtual card for {username}",
            "Requires": "pcscd.service"},
        "Service": {
            "Environment": f'SOFTHSM2_CONF="{conf_dir}/softhsm2.conf"',
            "WorkingDirectory": card_dir,
            "ExecStart": "/usr/bin/virt_cacard >> /var/log/virt_cacard.debug 2>&1",
            "KillMode": "process"
        },
        "Install": {"WantedBy": "multi-user.target"}
    }
    cnf = ConfigParser()
    cnf.optionxform = str

    if exists(path):
        name = split(path)[1].split(".", 1)
        name = name[0] + "-original." + name[1]
        backup_dir = utils.backup_(path, name)
        add_restore("file", path, backup_dir)

    with open(path, "w") as f:
        cnf.read_dict(default)
        cnf.write(f)
    env_logger.debug(f"Service file {path} for user '{username}' "
                     "is created.")


def setup_ca_():
    """Executes script for setting up local CA. All necessary files and
    directories will be created in path specified by ca_dir field in
    the configuration file.
    """
    ca_dir = read_env("CA_DIR")
    env_logger.debug("Start setup of local CA")

    try:
        run(["bash", SETUP_CA, "--dir", ca_dir])
        env_logger.debug("Setup of local CA is completed")
    except CalledProcessError:
        env_logger.error("Error while setting up local CA")
        exit(1)


def setup_virt_card_(user: dict):
    """
    Executes setup script fot virtual smart card

    Args:
        user: dictionary with user information
    """

    username, card_dir, passwd = user["name"], user["card_dir"], user["passwd"]
    cmd = ["bash", SETUP_VSC, "--dir", card_dir, "--username", username]
    if user["local"]:
        try:
            pwd.getpwnam(username)
        except KeyError:
            run(["useradd", username, "-m", ])
            env_logger.debug(f"Local user {username} is added to the system "
                             f"with a password {passwd}")
        finally:
            with Popen(['passwd', username, '--stdin'], stdin=PIPE,
                       stderr=PIPE, encoding="utf-8") as proc:
                proc.communicate(passwd)
            env_logger.debug(f"Password for user {username} is updated to {passwd}")
        create_cnf(username, conf_dir=join(card_dir, "conf"))
        cnf = ConfigParser()
        cnf.optionxform = str
        with open("/etc/sssd/sssd.conf", "r") as f:
            cnf.read_file(f)

        if f"certmap/shadowutils/{username}" not in cnf.sections():
            cnf.add_section(f"certmap/shadowutils/{username}")

        cnf.set(f"certmap/shadowutils/{username}", "matchrule",
                f"<SUBJECT>.*CN={username}.*")
        with open("/etc/sssd/sssd.conf", "w") as f:
            cnf.write(f)
        env_logger.debug("Match rule for local user is added to /etc/sssd/sssd.conf")
    try:
        if user["cert"]:
            cmd += ["--cert", user["cert"]]
        else:
            raise KeyError
        if user["key"]:
            cmd += ["--key", user["key"]]
        else:
            raise KeyError()
    except KeyError:
        ca_dir = read_env("CA_DIR")
        cmd += ["--ca", ca_dir]
        env_logger.debug(f"Key or certificate for user {username} "
                         f"is not present. New pair of key and cert will "
                         f"be generated by local CA from {ca_dir}")

    env_logger.debug(f"Start setup of virtual smart card for user {username} "
                     f"in {card_dir}")
    try:
        run(cmd)
        env_logger.info(f"Setup of virtual smart card for user {username} "
                        f"is completed")
    except CalledProcessError:
        env_logger.error("Error while setting up virtual smart card.")
        raise


def check_semodule():
    """Checks if specific SELinux module for virtual smart card is installed.
    This is implemted be checking the hardcoded name for the module (virtcacard)
    to be present in the list of SELinux modules. If this name is not present in
    the list, than virtcacard.cil file would be created in conf/ sub-directory
    in the CA directory specified by the configuration file.
    """
    result = run(["semodule", "-l"])
    if "virtcacard" not in result.stdout:
        env_logger.debug(
            "SELinux module for virtual smart cards is not present in the "
            "system. Installing...")
        conf_dir = join(read_env("CA_DIR"), 'conf')
        module = """
(allow pcscd_t node_t(tcp_socket(node_bind)))

; allow p11_child to read softhsm cache - not present in RHEL by default
(allow sssd_t named_cache_t(dir(read search)))"""
        with open(f"{conf_dir}/virtcacard.cil", "w") as f:
            f.write(module)
        try:
            run(["semodule", "-i", f"{conf_dir}/virtcacard.cil"])
            env_logger.debug(
                "SELinux module for virtual smart cards is installed")
        except CalledProcessError:
            env_logger.error("Error while installing SELinux module "
                             "for virt_cacard")
            raise

        try:
            run(["systemctl", "restart", "pcscd"])
            env_logger.debug("pcscd service is restarted")
        except CalledProcessError:
            env_logger.error("Error while restarting the pcscd service")
            raise


def prepare_dir(dir_path: str, conf=True):
    """Create diretory on given path and optionly create the conf/ sub-directory
     insied.
     Args:
         dir_path: path where directory need to be created.
         conf: specifies if conf/ sub-derectory need to be created in the given
               directory (default True).
     """
    Path(dir_path).mkdir(parents=True, exist_ok=True)
    env_logger.debug(f"Directory {dir_path} is created")
    if conf:
        Path(join(dir_path, "conf")).mkdir(parents=True, exist_ok=True)
        env_logger.debug(f"Directory {join(dir_path, 'conf')} is created")


def prep_tmp_dirs():
    """
    Prepair directory structure for test environment. All paths are taken from
    previously loaded env file.
    """
    paths = [read_env(path, cast=str) for path in ("CA_DIR", "TMP", "BACKUP")] + \
            [join(read_env("CA_DIR"), "conf")]
    for path in paths:
        prepare_dir(path, conf=False)


def install_ipa_client_(ip: str, passwd: str, server_hostname: str = None):
    """Install ipa-client packge to the system and run ipa-advice script for
    configuring the client for smart card support.
    Args:
        ip: IP address of IPA server
        passwd: root password from IPA server (needed to obtain ipa-advice
                script). NOTE: currently passwd would be used both for login to
                the system with root and for obtaining admin kerberos ticke on
                the server.
        server_hostname: hostname of IPA server
    """
    env_logger.debug(f"Start installation of IPA client")
    if server_hostname is None:
        server_hostname = read_config("ipa_server_hostname")

    entry = f"{ip} {server_hostname}"
    hosts_entry_present = False
    with open("/etc/hosts", "r") as f:
        if entry in f.read():
            hosts_entry_present = True
    if not hosts_entry_present:
        with open("/etc/hosts", "a") as f:
            f.write(f"{entry}\n")

    env_logger.debug(f"New entry {entry} is added to /etc/hosts")

    try:
        run(["bash", INSTALL_IPA_CLIENT, "--ip", ip, "--root", passwd,
            "--server-hostname", server_hostname])
        env_logger.debug("IPA client is configured on the system. "
                         "Don't forget to add IPA user by add-ipa-user command :)")
    except CalledProcessError:
        env_logger.error("Error while installing IPA client on local host")
        raise


def add_ipa_user_(user: dict, ipa_hostname: str = None):
    """Add IPA user to IPA server and prepare laocal directories for virtual
    smart card for this user. Also, function generate CSR for this user and
    requests the certificate from the CA located on IPA server.
    Args:
        user:  dictionary with username ('name' field), directory where
               virtual smart card to be created ('card_dir' field). This directory
               would contain also cerficiate & private key, all other sub-directories
               need be virtual smart card (tokens, db, etc.). Also, dictionary can
               contain custom paths to key, certificate and CSR where to save
               corresponding items.
        ipa_hostname: hostname of IPA server. If non, tryes to read
                         ipa_server_hostname field from the configuration file
    """
    username, user_dir = user["name"], user["card_dir"]
    cert_path = user["cert"] if "cert" in user.keys() else f"{user_dir}/cert.pem"
    key_path = user["key"] if "key" in user.keys() else f"{user_dir}/private.key"
    csr_path = user["csr"] if "csr" in user.keys() else f"{user_dir}/cert.csr"
    env_logger.debug(f"Adding user {username} to IPA server")
    ipa_admin_passwd = read_config("ipa_server_admin_passwd")
    if ipa_hostname is None:
        ipa_hostname = read_config("ipa_server_hostname")
        if ipa_hostname is None:
            raise UnspecifiedParameter("ipa_hostname")

    client = pipa.ClientMeta(ipa_hostname, verify_ssl=False)
    client.login("admin", ipa_admin_passwd)
    try:
        client.user_add(username, username, username, username)
    except pipa.exceptions.DuplicateEntry:
        env_logger.warning(f"User {username} already exists in the IPA server "
                           f"{ipa_hostname}")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    prepare_dir(user_dir)

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    try:
        run(["openssl", "req", "-new", "-days", "365",
             "-nodes", "-key", key_path, "-out",
             csr_path, "-subj", f"/CN={username}"])
    except CalledProcessError:
        env_logger.error(f"Error while generating CSR for user {username}")
        raise
    try:
        run(["ipa", "cert-request", csr_path, "--principal",
             username, "--certificate-out", cert_path])
    except CalledProcessError:
        env_logger.error(f"Error while requesting the certificate for user "
                         f"{username} from IPA server")
        raise

    env_logger.debug(f"User {username} is updated on IPA server. "
                     f"Cert and key stored into {user_dir}")


def setup_ipa_server_():
    run(["bash", SETUP_IPA_SERVER])


def general_setup(install_missing: bool = True):
    """Executes script for general setup of the system. General setup includes
    check for presense of required packages. Once this function is called,
    READY environment variable is added to .env file and set to 1. When READY
    is 1, script is not executed again, even if this function is called again.
    Args:
        install_missing: specifies if missing packages need to be automatically
                         installed.
    """

    if read_env("READY", cast=int, default=0) != 1:
        check_semodule()
        packages = ["softhsm", "sssd-tools", "httpd", "sssd", "sshpass"]
        try:
            with open('/etc/redhat-release', "r") as f:
                if "Red Hat Enterprise Linux release 9" not in f.read():
                    run("dnf module enable -y idm:DL1")
                    run("dnf install @idm:DL1 -y")
                    env_logger.debug("idm:DL1 module is installed")
                    
                    run("dnf -y copr enable jjelen/vsmartcard")
                    env_logger.debug("Copr repo for virt_cacard is enabled")
                    
                    run("dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -y")
                    env_logger.debug("EPEL repository is installed")
            run("dnf install virt_cacard vpcd -y")
            env_logger.debug("virt_cacard is installed")
            env_logger.debug("VPCD is installed")
            for pkg in packages:
                out = run(["rpm", "-qa", pkg])

                if pkg not in out.stdout:
                    if install_missing:
                        env_logger.warning(f"Package {pkg} is not installed on the system. Installing...")
                        run(f"dnf install {pkg} -y")
                        env_logger.debug(f"Package {pkg} is installed")
                    else:
                        env_logger.error(
                            f"Package {pkg} is required for testing, "
                            "but it is not installed on the system.")
                        raise SCAutolibException(
                        f"Package {pkg} is required for testing, but it is not "
                        f"installed on the system.")
                else:
                    env_logger.debug(f"Package {out.stdout.strip()} is present")
            run(['dnf', 'groupinstall', "Smart Card Support", '-y'])
            env_logger.debug("Smart Card Support group in installed.")
        except Exception as e:
            env_logger.error(e)
            env_logger.error("General setup is failed")
            raise
    env_logger.info("General setup is done")


def create_sc(sc_user: dict):
    """Function that joins steps for creating virtual smart card.
    Args:
        sc_user: dictionary with username ('name' field), directory where
        virtual smart card to be created ('card_dir' field). This directory
        would contain also cerficiate & private key, all other sub-directories
        need be virtual smart card (tokens, db, etc.)
    """
    name, card_dir = sc_user["name"], sc_user["card_dir"]
    prepare_dir(card_dir)
    create_softhsm2_config(card_dir)
    create_virt_card_service(name, card_dir)
    setup_virt_card_(sc_user)


def check_config(conf: str) -> bool:
    """Check if all required fields are present in the config file. Warn user if
    some fields are missing.
    Args:
        conf: path to configuration file in YAML format
    Return:
        True if config file contain everyting what is needed. Otherwise False.
    """
    with open(conf, "r") as file:
        config_data = yaml.load(file, Loader=yaml.FullLoader)
        assert config_data, "Data are not loaded correctly."
    result = True
    fields = ("root_passwd", "ca_dir", "ipa_server_root", "ipa_server_ip",
              "ipa_server_hostname", "ipa_client_hostname", "ipa_domain",
              "ipa_realm", "ipa_server_admin_passwd", "local_user", "ipa_user")
    config_fields = config_data.keys()
    for f in fields:
        if f not in config_fields:
            env_logger.warning(f"Field {f} is not present in the config.")
            result = False
    if result:
        env_logger.info("Configuration file is OK.")
    return result


def add_restore(type_: str, src: str, backup: str = None):
    """Add new item to be restored in the cleanup phase.

    Args:
        type_: type of item. Cane be one of user, file or dir. If type is not
               matches any of mentioned types, warning is written, but item
               is added.
        src: for file and dir should be an original path. For type == user
             should be username
        backup: applicable only for file and dir type. Path where original
                source was placed.
    """
    with open(read_env("CONF"), "r") as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
        assert data

    if type_ not in ("user", "file", "dir"):
        env_logger.warning(f"Type {type_} is not know, so this item can't be "
                           f"correctly restored")
    data["restore"].append({"type": type_, "src": src, "backup_dir": backup})

    with open(read_env("CONF"), "w") as f:
        yaml.dump(data, f)


def cleanup_(restore_items: list):
    """Cleans the system after library setup testing environment.
    Args:
        restore_items: list of items to be restore. Item is a dict with specific
        fields. Item has to tocntain at list type (file, dir, user) and src
        (username if type is 'user'). Type field can also be some custom type,
        but it wouldnt be restore by this function.
    """
    for item in restore_items:
        type_ = item['type']
        src = item['src'] if type_ != "user" else item["username"]
        backup_dir = item["backup_dir"] if "backup_dir" in item.keys() else None

        if type_ == "file":
            if backup_dir:
                copyfile(backup_dir, src)
                env_logger.debug(f"File {src} is restored form {backup_dir}")
            else:
                remove(src)
                env_logger.debug(f"File {src} is deleted")
        elif type_ == "dir":
            rmtree(src, ignore_errors=True)
            env_logger.debug(f"Directory {src} is deleted")
            if backup_dir:
                copytree(backup_dir, src)
                env_logger.debug(f"Directory {src} is restored form {backup_dir}")

        elif type_ == "user":
            username = item["username"]
            run(["userdel", username, "-r"])
            env_logger.debug(f"User {username} is delete with it home directory")
        else:
            env_logger.warning(f"Skip item with unknow type '{type_}'")


def run(cmd) -> subprocess.CompletedProcess:
    if type(cmd) == str:
        cmd = cmd.split(" ")
    return subprocess.run(cmd, stdout=PIPE, check=True, encoding="utf-8", 
                          stderr=PIPE)
