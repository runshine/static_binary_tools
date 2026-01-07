#!/bin/bash

source "$(cd `dirname $0`;pwd)/../common/prepare_dir.sh"
source "$(cd `dirname $0`;pwd)/../common/utils_func.sh"
source "$(cd `dirname $0`;pwd)/../common/arch_detect.sh"

apt update && apt-get -y install curl wget unzip

VERSION="latest"
#mv ../ttyd-linux-aarch64.tar.gz "$INSTALL_DIR/ttyd-v1.7.7-linux-aarch64.tar.gz
aarch64_linux_data="/build/ssh-binaries-for-aarch64.zip"
x86_64_linux_data="/build/ssh-binaries-for-x86-64-small.zip"
armhf_linux_data="/build/ssh-binaries-for-armv7-eabihf.zip"
armel_linux_data="/build/ssh-binaries-for-armel.zip"

generate_sshd_config(){
  sshd_config_file="$1"
  if [ ! -f "$sshd_config_file" ];then
    echo "sshd_config_file must be exist: ${sshd_config_file}"
    exit 255
  fi

  cat << EOF > "$sshd_config_file"

#       $OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/bin:/usr/bin:/sbin:/usr/sbin:/opt/openssh/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Port 11192
#AddressFamily any
ListenAddress 0.0.0.0
#ListenAddress ::

HostKey /opt/openssh/etc/ssh_host_rsa_key
HostKey /opt/openssh/etc/ssh_host_ecdsa_key
HostKey /opt/openssh/etc/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile      /opt/openssh/etc/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /opt/openssh/etc/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
PasswordAuthentication no
PermitEmptyPasswords no

# Change to no to disable s/key passwords
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin prohibit-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
#UsePAM no

AllowAgentForwarding yes
AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
PidFile /opt/openssh/run/sshd.pid
#MaxStartups 10:30:100
PermitTunnel yes
#ChrootDirectory  none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem       sftp    /opt/openssh/libexec/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server

EOF
}


process_ssh_data(){
  source_data="$1"
  target_data="$2"
  source_dir="$(dirname "${source_data}")"
  echo "start process ssh_data file: ${source_data}"
  cd "${source_dir}"
  if [ ! -d "$source_dir/tmp" ];then
    mkdir -p "$source_dir/tmp"
    unzip "$source_data" -d "$source_dir/tmp"
    for file in $source_dir/tmp/openssh*.tgz
    do
      echo "start process file: ${file}"
      cd "$source_dir/tmp"
      if [ ! -d "$source_dir/tmp/tmp" ];then
        mkdir "$source_dir/tmp/tmp"
      fi
      echo "try decompress tar file: ${file}"
      tar -zxvf "${file}" -C "$source_dir/tmp/tmp"
      cd "$source_dir/tmp/tmp/opt"

      generate_sshd_config "$source_dir/tmp/tmp/opt/openssh/etc/ssh/sshd_config"

      cd openssh
      tar -czvf ../openssh.tar.gz .
      cd ..
      mv openssh.tar.gz "$2"
    done
  fi
  if [ -d "$source_dir/tmp" ];then
    rm -rf "$source_dir/tmp"
  fi
}

process_ssh_data "$aarch64_linux_data" "${INSTALL_DIR}/openssh-${VERSION}-linux-aarch64.tar.gz"
process_ssh_data "$x86_64_linux_data" "${INSTALL_DIR}/openssh-${VERSION}-linux-x86_64.tar.gz"
process_ssh_data "$armhf_linux_data" "${INSTALL_DIR}/openssh-${VERSION}-linux-armhf.tar.gz"
process_ssh_data "$armel_linux_data" "${INSTALL_DIR}/openssh-${VERSION}-linux-armel.tar.gz"

