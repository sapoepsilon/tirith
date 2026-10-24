#!/usr/bin/env bash
# Breach lab: a deliberately vulnerable Ubuntu box (VM "metasploitable", 192.168.50.100).
#
#   scp provision/breach-lab.sh root@192.168.50.100:/root/
#   ssh root@192.168.50.100 bash /root/breach-lab.sh
#
# The autoinstaller already placed this file at /root/breach-lab.sh and ran it once from
# breach-lab.service; running it again is harmless. Every service is a stock Debian/Ubuntu package with its
# own systemd unit and is left ENABLED after install (allowed by UFW) -- that is the point of the lab.
# Idempotency: packages and their services are skipped when present, configs are rewritten from this file,
# the DVWA checkout is reused and the database is only seeded when it is empty.
#
# Nothing here needs the Tirith repo: DVWA is cloned from its pinned upstream, everything else is apt.
# Every credential is a dummy lab value and is repeated in BREACH-LAB.md (/root, and served at /BREACH-LAB.md).
#
# Rerunning is idempotent: apt and the service skips are guarded, every config is rewritten from this file,
# the DVWA checkout is reset to its pin, credentials are replaced, and the database is only seeded when empty.
# A failed step names itself; fix the environment, run it again.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export UCF_FORCE_CONFFOLD=1

STEP="startup"
trap 'printf "\n>>> FAILED at step: %s (line %s)\n" "$STEP" "$LINENO" >&2' ERR
step() { STEP="$1"; printf '\n>>> %s\n' "$1"; }
say() { printf '    %s\n' "$*"; }

# --- credentials (dummy lab values, mirrored in BREACH-LAB.md) -------------------------------------------
DVWA_REPO="${DVWA_REPO:-https://github.com/digininja/DVWA.git}"
DVWA_REF="${DVWA_REF:-master}"
DVWA_DIR=/var/www/html/dvwa
DVWA_URI=/dvwa
DVWA_DB=dvwa
DVWA_USER=dvwa
DVWA_PASS='p@ssw0rd'
DAV_USER=davuser
DAV_PASS=davpass
JENKINS_PORT=8088
JENKINS_KEYRING=/usr/share/keyrings/jenkins-keyring.asc
NOTES=/root/BREACH-LAB.md

# The second, parallel Metasploitable 3 box (guest 163) is published on the pve3 host leg, 81xx instead of
# 8x: run the provisioner there with `META3_HOST=192.168.50.161` set. 8162 is its Apache (:80) and the
# mapped entry in Tirith's scope; provision/meta3-shim.sh owns the host side, and the notes then name it.
META3_HOST="${META3_HOST:-}"
# shellcheck disable=SC2034  # all three are expanded inside the quoted notes heredoc
WEB="${META3_HOST:+$META3_HOST:8162}"      # empty = the guest's own port map (guest 162, 192.168.50.100)
# shellcheck disable=SC2034
TOMCAT_URI=${META3_HOST:+$META3_HOST:8161}  # ...so every absolute URL in the notes is left as on that profile
# shellcheck disable=SC2034
JENKINS_URI=${META3_HOST:+$META3_HOST:8168}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo "needs systemd (run inside the VM, not in a chroot)" >&2; exit 1; }
for tool in curl git mysql php; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# Classic PATH files so units started by systemd (jenkins) find a normal PATH like a login shell.
printf '%s\n' 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' 'export PATH' \
  >/etc/environment
printf '%s\n' 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' >/root/.bashrc

# --- 1. packages ----------------------------------------------------------------------------------------
step "packages"
apt-get -y -o DPkg::Lock::Timeout=300 update
apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef \
  -o Dpkg::Options::=--force-confold upgrade
apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef \
  -o Dpkg::Options::=--force-confold install --no-install-recommends \
  openssh-server ufw curl ca-certificates git unzip \
  vsftpd samba nfs-kernel-server subversion \
  apache2 davfs2 libapache2-mod-php libapache2-mod-dav libapache2-mod-svn php php-mysql \
  mariadb-server mariadb-client phpmyadmin default-mysql-client \
  openjdk-21-jdk-headless tomcat10

# Jenkins: the Debian repo key, pinned to this release and this architecture only.
if [[ ! -f $JENKINS_KEYRING ]]; then
  curl -fsSLo "$JENKINS_KEYRING" https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
fi
if [[ ! -f /etc/apt/sources.list.d/jenkins.list ]]; then
  printf 'deb [arch=%s signed-by=%s] https://pkg.jenkins.io/debian-stable binary/\n' \
    "$(dpkg --print-architecture)" "$JENKINS_KEYRING" \
    >/etc/apt/sources.list.d/jenkins.list
  apt-get -y -o DPkg::Lock::Timeout=300 update
fi
if ! dpkg-query -W -f='${Status}' jenkins 2>/dev/null | grep -qx 'install ok installed'; then
  apt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold install jenkins </dev/null
fi

# phpMyAdmin (apt) and the DVWA checkout are fetched here, not in a later step.
curl -fsSL -o /tmp/phpmyadmin.deb \
  "https://files.phpmyadmin.net/phpMyAdmin/5.2.2/phpMyAdmin-5.2.2-all-languages.tar.gz"

# --- 2. sshd: root by key only --------------------------------------------------------------------------
step "sshd key-only root"
install -d -m 0700 /root/.ssh
printf '%s\n' \
  'Include /etc/ssh/sshd_config.d/*.conf' \
  'PermitRootLogin prohibit-password' \
  'PasswordAuthentication no' \
  'KbdInteractiveAuthentication no' \
  'PubkeyAuthentication yes' \
  >/etc/ssh/sshd_config
systemctl enable ssh
systemctl restart ssh

# --- 3. firewall ----------------------------------------------------------------------------------------
step "firewall"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp       comment 'ssh'
ufw allow 21/tcp       comment 'vsftpd'
ufw allow 80/tcp       comment 'apache: dvwa, phpmyadmin, webdav, svn'
ufw allow 137/udp      comment 'samba netbios'
ufw allow 138/udp      comment 'samba netbios'
ufw allow 139/tcp      comment 'samba'
ufw allow 445/tcp      comment 'samba'
ufw allow 2049/tcp     comment 'nfs'
ufw allow 3306/tcp     comment 'mariadb'
ufw allow 8080/tcp     comment 'tomcat10'
ufw allow 8088/tcp     comment 'jenkins'
ufw --force enable

# --- 4. vsftpd: anonymous read/write of a drop box ------------------------------------------------------
step "vsftpd"
install -d -m 0555 /srv/ftp/incoming
chown root:root /srv/ftp
# Default umask 022: anonymous PUTs land world-readable, so they can be fetched again afterwards.
printf '%s\n' \
  'listen=YES' \
  'listen_ipv6=NO' \
  'anonymous_enable=YES' \
  'anon_root=/srv/ftp' \
  'no_anon_password=YES' \
  'anon_upload_enable=YES' \
  'anon_mkdir_write_enable=YES' \
  'write_enable=YES' \
  'local_enable=YES' \
  'local_umask=022' \
  'anon_umask=022' \
  'dirmessage_enable=YES' \
  'xferlog_enable=YES' \
  'use_localtime=YES' \
  'seccomp_sandbox=NO' \
  'secure_chroot_dir=/var/run/vsftpd/empty' \
  'pam_service_name=vsftpd' \
  >/etc/vsftpd.conf
systemctl enable vsftpd
systemctl restart vsftpd

# --- 5. samba: public guest share -----------------------------------------------------------------------
step "samba"
install -d -m 0777 /srv/smb/public
chown nobody:nogroup /srv/smb/public
printf '%s\n' \
  '[global]' \
  '   workgroup = WORKGROUP' \
  '   server string = breach-lab' \
  '   map to guest = Bad User' \
  '   log file = /var/log/samba/log.%m' \
  '   max log size = 1000' \
  '   security = user' \
  "   # Anonymous RPC as well, so smbclient -L lists the share without a login attempt." \
  '   restrict anonymous = 0' \
  '   printcap name = /dev/null' \
  '   load printers = no' \
  '   disable spoolss = yes' \
  '' \
  '[public]' \
  '   path = /srv/smb/public' \
  '   browseable = yes' \
  '   read only = no' \
  '   guest ok = yes' \
  '   force user = nobody' \
  >/etc/samba/smb.conf
systemctl enable smbd nmbd
systemctl restart smbd nmbd

# --- 6. nfs: world-readable export ----------------------------------------------------------------------
step "nfs"
install -d -m 0755 /srv/nfs/demo
# rw on the export, ro for clients: the deliberate finding is the open (`*`) export, writes stay local.
printf '%s\n' '# breach-lab: exported to everyone read-only, anonymous access allowed' '/srv/nfs/demo *(rw,ro,all_squash,insecure)' \
  >/etc/exports
# Optional exports parse errors must not wedge the unit: check, apply, then explicitly (re)start.
exportfs -ra
systemctl enable nfs-kernel-server
systemctl restart nfs-kernel-server
exportfs -ra

# --- 7. mariadb: bound everywhere, root without a password ----------------------------------------------
# The account DDL below logs in as root over the unix socket while there is no drop-in yet: stock Ubuntu
# authorises root through auth_socket, so no password is needed. Every later step, including an idempotent
# rerun, reaches the server over TCP with the empty password -- the bind drop-in therefore comes last and the
# restart above has already loaded whatever state the server was in.
step "mariadb"
install -d -m 0755 /etc/mysql/mariadb.conf.d
rm -f /etc/mysql/mariadb.conf.d/99-breach-lab.cnf
printf '%s\n' '[mysqld]' 'port = 3306' 'skip-name-resolve' \
  >/etc/mysql/mariadb.conf.d/99-breach-lab.cnf
systemctl enable mariadb
systemctl restart mariadb
for _ in $(seq 1 60); do
  mysqladmin ping --silent >/dev/null 2>&1 && break
  sleep 0.5
done
mysqladmin ping --silent >/dev/null 2>&1 || { echo "mariadb did not come up" >&2; exit 1; }
# One passwordless root: reachable over the socket and, after the second restart, over TCP.
mysql <<SQL
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('');
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED VIA mysql_native_password USING PASSWORD('');
GRANT ALL ON *.* TO 'root'@'%' WITH GRANT OPTION;
CREATE DATABASE IF NOT EXISTS $DVWA_DB;
CREATE USER IF NOT EXISTS '$DVWA_USER'@'localhost' IDENTIFIED BY '$DVWA_PASS';
CREATE USER IF NOT EXISTS '$DVWA_USER'@'127.0.0.1' IDENTIFIED BY '$DVWA_PASS';
GRANT ALL ON $DVWA_DB.* TO '$DVWA_USER'@'localhost';
GRANT ALL ON $DVWA_DB.* TO '$DVWA_USER'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
# Now that both root rows accept the empty password, open the listener for the analyst.
printf '%s\n' '[mysqld]' 'bind-address = 0.0.0.0' 'port = 3306' 'skip-name-resolve' \
  >/etc/mysql/mariadb.conf.d/99-breach-lab.cnf
systemctl restart mariadb
for _ in $(seq 1 60); do
  mysqladmin ping --silent >/dev/null 2>&1 && break
  sleep 0.5
done

# --- 8. apache + php + phpmyadmin -----------------------------------------------------------------------
step "apache/php/phpmyadmin"
a2enmod -q rewrite headers dav dav_fs dav_svn auth_basic auth_digest env alias
a2dismod -q -f mpm_event
a2enmod -q mpm_prefork
install -d -m 0755 /etc/php/*/apache2/conf.d
printf '%s\n' \
  'allow_url_fopen = On' \
  'allow_url_include = On' \
  'display_errors = On' \
  'upload_max_filesize = 32M' \
  'post_max_size = 32M' \
  >/etc/php/*/apache2/conf.d/99-breach-lab.ini
printf '%s\n' 'ServerName localhost' >/etc/apache2/conf-available/servername.conf
a2enconf -q servername

rm -rf /var/www/html/index.html
printf '%s\n' '<h1>breach-lab</h1><ul><li><a href="/dvwa/">/dvwa</a></li><li><a href="/phpmyadmin/">/phpmyadmin</a></li><li><a href="/dav/">/dav</a></li><li><a href="/svn/demo/">/svn/demo</a></li></ul>' \
  >/var/www/html/index.html

# phpMyAdmin: config cookie auth, root with the empty password allowed.
install -d -m 0755 /etc/phpmyadmin /var/lib/phpmyadmin/tmp
chown -R www-data:www-data /var/lib/phpmyadmin
printf '%s\n' 'AllowNoPassword=true' >/etc/phpmyadmin/conf.d/99-breach-lab.php

# --- 9. DVWA --------------------------------------------------------------------------------------------
step "dvwa"
if [[ ! -d $DVWA_DIR/.git ]]; then
  git clone --branch "$DVWA_REF" --depth 1 "$DVWA_REPO" "$DVWA_DIR"
else
  git -C "$DVWA_DIR" fetch --depth 1 origin "$DVWA_REF"
  git -C "$DVWA_DIR" reset --hard FETCH_HEAD
fi
install -d -m 0777 "$DVWA_DIR/hackable/uploads"
chown -R www-data:www-data "$DVWA_DIR"
# Low security for every module (upstream also ships the setup page's own defaults this way), the database
# user created above. The checkout sits under /dvwa, so the security cookie is scoped there as well.
# shellcheck disable=SC2016  # these are PHP snippets, nothing expands here
printf '%s\n' \
  '<?php' \
  "\$DBMS = getenv('DBMS') ?: 'MySQL';" \
  '$_DVWA = array();' \
  '$_DVWA["db_server"] = getenv("DB_SERVER") ?: "127.0.0.1";' \
  '$_DVWA["db_database"] = getenv("DB_DATABASE") ?: "dvwa";' \
  '$_DVWA["db_user"] = getenv("DB_USER") ?: "dvwa";' \
  "\\\$_DVWA['db_password'] = getenv('DB_PASSWORD') ?: '$DVWA_PASS';" \
  '$_DVWA["db_port"] = getenv("DB_PORT") ?: "3306";' \
  '$_DVWA["recaptcha_public_key"] = getenv("RECAPTCHA_PUBLIC_KEY") ?: "";' \
  '$_DVWA["recaptcha_private_key"] = getenv("RECAPTCHA_PRIVATE_KEY") ?: "";' \
  '$_DVWA["default_security_level"] = "low";' \
  '$_DVWA["default_locale"] = getenv("DEFAULT_LOCALE") ?: "en";' \
  '$_DVWA["disable_authentication"] = getenv("DISABLE_AUTHENTICATION") ?: false;' \
  'define("MYSQL", "mysql");' \
  'define("SQLITE", "sqlite");' \
  '$_DVWA["SQLI_DB"] = getenv("SQLI_DB") ?: MYSQL;' \
  >"$DVWA_DIR/config/config.inc.php"
chown www-data:www-data "$DVWA_DIR/config/config.inc.php"
# The security cookie is set for "/": a module a subdirectory deep would lose it and fall back to the
# default level of `impossible`. Scope it to the app root, and pin the module URLs to it too.
sed -i "s|setcookie( 'security', \\\$pSecurityLevel, 0, \"/\"|setcookie( 'security', \\\$pSecurityLevel, 0, \"$DVWA_URI\"|" \
  "$DVWA_DIR/dvwa/includes/dvwaPage.inc.php"
sed -i "s|'url' => 'vulnerabilities/|'url' => '$DVWA_URI/vulnerabilities/|g" \
  "$DVWA_DIR/dvwa/includes/dvwaPage.inc.php"
grep -qF "'security', \\\$pSecurityLevel, 0, \"$DVWA_URI\"" "$DVWA_DIR/dvwa/includes/dvwaPage.inc.php" \
  || { echo "security cookie path was not rewritten" >&2; exit 1; }

# --- 10. webdav (basic auth) and svn (anonymous read) ---------------------------------------------------
step "webdav and svn"
install -d -m 0755 /srv/dav /var/lib/dav
chown www-data:www-data /var/lib/dav
htpasswd -bc /etc/apache2/dav.htpasswd "$DAV_USER" "$DAV_PASS"
chown root:www-data /etc/apache2/dav.htpasswd
chmod 0640 /etc/apache2/dav.htpasswd
rm -rf /srv/svn/demo
svnadmin create /srv/svn/demo
svn import -q --no-ignore -m 'demo: import DVWA vulnerabilities' \
  "$DVWA_DIR/vulnerabilities" "file:///srv/svn/demo/trunk" </dev/null
chown -R www-data:www-data /srv/svn
printf '%s\n' \
  'DavLockDB /var/lib/dav/DavLock' \
  '' \
  '<Location /dav>' \
  '  Dav On' \
  '  AuthType Basic' \
  '  AuthName "breach-lab dav"' \
  '  AuthUserFile /etc/apache2/dav.htpasswd' \
  '  Require valid-user' \
  '</Location>' \
  '' \
  '<Location /svn/demo>' \
  '  DAV svn' \
  '  SVNPath /srv/svn/demo' \
  '  <LimitExcept GET PROPFIND OPTIONS REPORT>' \
  '    Require all granted' \
  '  </LimitExcept>' \
  '</Location>' \
  >/etc/apache2/conf-available/breach-lab-webdav-svn.conf
a2enconf -q breach-lab-webdav-svn
systemctl enable apache2

# --- 11. tomcat 10: stock manager without an auth prompt ------------------------------------------------
step "tomcat10"
install -d -m 0755 /etc/systemd/system/tomcat10.service.d
printf '%s\n' \
  '[Service]' \
  'Environment=JAVA_OPTS=-Djava.security.egd=file:/dev/./urandom' \
  'Environment=CATALINA_OPTS=-Dorg.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true' \
  >/etc/systemd/system/tomcat10.service.d/breach-lab.conf
# Empty manager-gui password: Tomcat hides the basic-auth challenge and opens the GUI directly.
printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<tomcat-users xmlns="http://tomcat.apache.org/xml"' \
  '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
  '  xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"' \
  '  version="1.0">' \
  '  <role rolename="manager-gui"/>' \
  '  <role rolename="admin-gui"/>' \
  '  <user username="admin" password="" roles="manager-gui,admin-gui"/>' \
  '</tomcat-users>' \
  >/etc/tomcat10/tomcat-users.xml
if [[ ! -f /etc/tomcat10/Catalina/localhost/manager.xml ]]; then
  install -d -m 0755 /etc/tomcat10/Catalina/localhost
  # Empty RemoteAddrValve: the stock ctx only admits 127.0.0.1, the VM is addressed from outside.
  printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<Context privileged="true" antiResourceLocking="false"' \
    '  docBase="{catalina.home}/webapps/manager">' \
    '  <CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor"' \
    '    sameSiteCookies="strict" />' \
    '  <Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="" />' \
    '</Context>' \
    >/etc/tomcat10/Catalina/localhost/manager.xml
fi
systemctl enable tomcat10
systemctl restart tomcat10

# --- 12. jenkins LTS on 8088, setup wizard skipped, admin/admin ----------------------------------------
step "jenkins"
install -d -m 0755 /var/lib/jenkins/init.groovy.d /etc/systemd/system/jenkins.service.d
printf '%s\n' \
  'import jenkins.model.*' \
  'import hudson.model.*' \
  'import hudson.security.*' \
  '' \
  'instance = Jenkins.get()' \
  'instance.setInstallState(InstallState.INITIAL_SETUP_COMPLETED)' \
  'realm = instance.getSecurityRealm()' \
  'if (!(realm instanceof HudsonPrivateSecurityRealm)) {' \
  '  realm = new HudsonPrivateSecurityRealm(false)' \
  '  instance.setSecurityRealm(realm)' \
  '}' \
  'if (instance.getAuthorizationStrategy() !instanceof FullControlOnceLoggedInAuthorizationStrategy) {' \
  '  strategy = new FullControlOnceLoggedInAuthorizationStrategy()' \
  '  strategy.setAllowAnonymousRead(false)' \
  '  instance.setAuthorizationStrategy(strategy)' \
  '}' \
  'if (realm.getUser("admin") == null) {' \
  '  realm.createAccount("admin", "admin")' \
  '}' \
  'instance.save()' \
  >/var/lib/jenkins/init.groovy.d/10-breach-lab.groovy
chown -R jenkins:jenkins /var/lib/jenkins/init.groovy.d
printf '%s\n' \
  '[Service]' \
  "Environment=JENKINS_PORT=$JENKINS_PORT" \
  'Environment=JENKINS_LISTEN_ADDRESS=0.0.0.0' \
  'Environment=JENKINS_ARGS=--prefix=/ --webroot=/var/cache/jenkins/war' \
  >/etc/systemd/system/jenkins.service.d/breach-lab.conf
systemctl enable jenkins
systemctl restart jenkins

# --- 13. seed DVWA through its own setup page ----------------------------------------------------------
step "dvwa seed"
jar=$(mktemp)
# "First time using DVWA" answers 302 to setup.php: that is up, so 302 counts as reachable as well.
for _ in $(seq 1 60); do
  curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1$DVWA_URI/setup.php" | grep -qE '^(200|302)$' && break
  sleep 0.5
done
curl -fs -o /dev/null "http://127.0.0.1$DVWA_URI/setup.php" \
  || { echo "apache/dvwa did not answer" >&2; exit 1; }
if ! mysql -uroot -N -e "SELECT 1 FROM $DVWA_DB.users LIMIT 1" >/dev/null 2>&1; then
  token=$(curl -s -c "$jar" -b "$jar" http://127.0.0.1$DVWA_URI/setup.php \
    | sed -n "s/.*user_token' value='\([0-9a-f]*\)'.*/\1/p" | head -n1)
  [[ -n $token ]] || { echo "no CSRF token on setup.php" >&2; exit 1; }
  curl -s -o /dev/null -c "$jar" -b "$jar" \
    --data "create_db=Create+%2F+Reset+Database&user_token=$token" \
    "http://127.0.0.1$DVWA_URI/setup.php"
  for _ in $(seq 1 20); do
    mysql -uroot -N -e "SELECT 1 FROM $DVWA_DB.users LIMIT 1" >/dev/null 2>&1 && break
    sleep 0.5
  done
fi
# First login pins the security cookie to low for this client, so a shell session starts insecure.
token=$(curl -s -c "$jar" -b "$jar" "http://127.0.0.1$DVWA_URI/login.php" \
  | sed -n "s/.*user_token' value='\([0-9a-f]*\)'.*/\1/p" | head -n1)
[[ -n $token ]] || { echo "no CSRF token on login.php" >&2; exit 1; }
curl -s -o /dev/null -c "$jar" -b "$jar" \
  --data "username=admin&password=password&Login=Login&user_token=$token" \
  "http://127.0.0.1$DVWA_URI/login.php"
rm -f "$jar"
mysql -uroot -N -e "SELECT user FROM $DVWA_DB.users" >/dev/null 2>&1 \
  || { echo "DVWA database was not seeded" >&2; exit 1; }

# --- 14. notes ------------------------------------------------------------------------------------------
step "notes"
cat >"$NOTES" <<'EOF'
# breach-lab -- 192.168.50.100

Deliberately vulnerable Ubuntu 26.04 VM (Proxmox guest 162). Everything below is a dummy value; never reuse
it. This file and the whole lab are produced by `bash /root/breach-lab.sh` (no step needs the Tirith repo);
that run is repeated with `systemctl start breach-lab.service` and logs to `/var/log/breach-lab.log`.

| Service | URL / address | Credential | Intended finding | Reset |
|---|---|---|---|---|
| vsftpd | `ftp://${WEB:-192.168.50.100}/` | `anonymous` / empty | anonymous read AND write of `/srv/ftp` (`anon_upload_enable=YES`) | `systemctl restart vsftpd` |
| Samba | `smb://${WEB:-192.168.50.100}/public` | guest, no password | guest-writable public share `/srv/smb/public` | `chmod 0777 /srv/smb/public; systemctl restart smbd` |
| Apache Tomcat 10 | `http://${TOMCAT_URI:-192.168.50.100:8080}/manager/html` | `admin` / empty | manager GUI without any auth prompt (empty-password user, RemoteAddrValve empty) | `systemctl restart tomcat10` |
| Jenkins | `http://${JENKINS_URI:-192.168.50.100:8088}/` | `admin` / `admin` | first-run wizard skipped with the default admin password | `systemctl restart jenkins` (init script recreates the account) |
| DVWA | `http://${WEB:-192.168.50.100}/dvwa/` | `admin` / `password` | every module at security `low`; login `davuser`/`davpass` for the API | rerun `/root/breach-lab.sh` |
| phpMyAdmin | `http://${WEB:-192.168.50.100}/phpmyadmin/` | `root` / empty | passwordless database administration | `systemctl restart mariadb` |
| MariaDB | `192.168.50.100:3306` | `root` / empty, `dvwa` / `p@ssw0rd` (db `dvwa`) | root over TCP without a password, bound `0.0.0.0` | rerun `/root/breach-lab.sh` |
| WebDAV | `http://${WEB:-192.168.50.100}/dav/` | `davuser` / `davpass` | basic auth over cleartext; `PUT`/`DELETE` on `/srv/dav` | `systemctl restart apache2` |
| SVN | `svn://`-less HTTP: `http://${WEB:-192.168.50.100}/svn/demo` | anonymous | repository readable without credentials; history in `/srv/svn/demo/db` | `rm -rf /srv/svn/demo` then rerun the script |
| NFS | `192.168.50.100:/srv/nfs/demo` | none | world-readable export (`*`, `ro`, `all_squash`) | `exportfs -ra; systemctl restart nfs-kernel-server` |

Other facts for an analyst: SSH is key-only for root (`PermitRootLogin prohibit-password`), no password auth.
UFW allows only 21, 22, 80, 137-138/udp, 139, 445, 2049, 3306, 8080, 8088. DVWA's security level is kept in a
`security` cookie; reset it with the "DVWA Security" page or by logging in again after clearing cookies.

## Resetting

Rerunning `/root/breach-lab.sh` is idempotent per service and pairwise: it re-creates the samba share, vsftpd
drop box, dav user, svn repo and DAV/NFS exports; it does not touch a DVWA database that already has users
until `rm -rf /srv/svn/demo` or a drop of the `dvwa` database is done, after which the next run seeds it again.
Service-specific resets are listed per row above.
EOF
chmod 0644 "$NOTES"
install -m 0644 "$NOTES" /var/www/html/BREACH-LAB.md

# --- 15. provisioner service: one shot on first boot, the run itself keeps a log --------------------------
step "provisioner unit"
printf '%s\n' \
  '[Unit]' \
  'Description=breach-lab provisioner (once, first boot)' \
  'After=network-online.target' \
  'Wants=network-online.target' \
  'ConditionPathExists=/root/breach-lab.sh' \
  'Before=multi-user.target' \
  '' \
  '[Service]' \
  'Type=oneshot' \
  'RemainAfterExit=yes' \
  'ExecStart=/usr/bin/env bash /root/breach-lab.sh' \
  'StandardOutput=append:/var/log/breach-lab.log' \
  'StandardError=append:/var/log/breach-lab.log' \
  "ExecStartPost=/usr/bin/bash -c 'install -m 0644 $NOTES /var/www/html/BREACH-LAB.md'" \
  'TimeoutStartSec=0' \
  '' \
  '[Install]' \
  'WantedBy=multi-user.target' \
  >/etc/systemd/system/breach-lab.service
systemctl daemon-reload
systemctl enable breach-lab.service

step "final state"
systemctl is-active ssh vsftpd smbd nmbd nfs-kernel-server mariadb apache2 tomcat10 jenkins \
  | paste -d' ' <(printf '%s\n' ssh vsftpd smbd nmbd nfs-kernel-server mariadb apache2 tomcat10 jenkins) -
ufw --force status verbose | sed -n '1,20p'
say "notes: $NOTES (also http://192.168.50.100/BREACH-LAB.md)"
say "done"