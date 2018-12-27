#!/bin/bash
function header {

echo
echo 
echo "                        Audit Script                           "
echo "     SUSE Linux Enterprise Server 11 - Security Auditor        "
echo "                     Hamed Izadi (@hezd)                       "
echo
echo "###############################################################"
echo "###############################################################"
echo

}

function main_manual {

  func_name=$1
  echo "||| ${func_name}"
  echo
  shift
  args=$@
  ${func_name} ${args}
  line

}

function main_auto {

  func_name=$1
  shift
  args=$@
  ${func_name} ${args}
  if [[ "$?" -eq 0 ]]; then
    tput setaf 2; echo ${func_name} ${args} OK
    echo ; tput setaf 7;
  else
    tput setaf 1; echo ${func_name} ${args} ERROR
    echo ; tput setaf 7;
  fi

}


function line {
  echo 
  tput setaf 7; echo "######################## MANUAL CHECK #########################"
  echo
}

FSTAB='/etc/fstab'

function 1_Install_Updates_Patches_and_Additional_Security_Software {

  zypper list-updates || return

}

function 2_Create_Separate_Partition_for_tmp {

  local filesystem="/tmp"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return

}

function 3_Set_nodev_option_for_tmp_Partition {

  local filesystem="/tmp"
  local mnt_option="nodev"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep "${mnt_option}" || return

}

 function 4_Set_nosuid_option_for_tmp_Partition {

  local filesystem="/tmp"
  local mnt_option="nosuid"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep "${mnt_option}" || return

}

function 5_Set_noexec_option_for_tmp_Partition {

  local filesystem="/tmp"
  local mnt_option="noexec"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep "${mnt_option}" || return

}

function 6_Create_Separate_Partition_for_var {

  local filesystem="/var"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return

}

function 7_Bind_Mount_the_vartmp_directory_to_tmp {

  local directory="/var/tmp"
  local filesystem="/tmp"
  local E_NO_MOUNT_OUTPUT=1
  grep "^${filesystem}[[:space:]]" "${FSTAB}" | grep "${directory}" || return

  local grep_mount
  grep_mount=$(mount | grep "^${filesystem}[[:space:]]" | grep "${directory}")

  local fs_dev
  local dir_dev
  fs_dev="$(mount | grep "[[:space:]]${filesystem}[[:space:]]" | cut -d" " -f1)"
  dir_dev="$(mount | grep "[[:space:]]${directory}[[:space:]]" | cut -d" " -f1)"
  if [[ -z "${grep_mount}" ]] && [[ "${fs_dev}" != "${dir_dev}" ]] ; then
    return "${E_NO_MOUNT_OUTPUT}"
  fi

}

function 8_Create_Separate_Partition_for_var_log {

  local filesystem="/var/log"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return

}

function 9_Create_Separate_Partition_for_varlog_audit {

  local filesystem="/var/log/audit"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return

}

function 10_Create_Separate_Partition_for_home {

  local filesystem="/home"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return

}

function 11_Add_nodev_Option_to_home {

  local filesystem="/home"
  local mnt_option="nodev"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep "${mnt_option}" || return

}

function 12_Add_nodev_Option_to_Removable_Media_Partitions {

  echo "#mount"
  mount

}

function 13_Add_noexec_Option_to_Removable_Media_Partitions {
  
  echo "#mount"
  mount

}

function 14_Add_nosuid_Option_to_Removable_Media_Partitions {

  echo "#mount"
  mount

}

function 15_Add_nodev_Option_to_devshm_Partition {

  local filesystem="/dev/shm"
  local mnt_option="nodev"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep "${mnt_option}" || return

}

function 16_Add_nosuid_Option_to_devshm_Partition {

  local filesystem="/dev/shm"
  local mnt_option="nosuid"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep "${mnt_option}" || return
 
}

function 17_Add_noexec_Option_to_devshm_Partition {

  local filesystem="/dev/shm"
  local mnt_option="noexec"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep "${mnt_option}" || return
 
}

function 18_Set_Sticky_Bit_on_All_World_Writable_Directories {

  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' sudo find '{}' -xdev -type d \
\( -perm -0002 -a ! -perm -1000 \))"
  [[ -z "${dirs}" ]] || return

}

function 19_Disable_Mounting_of_cramfs_Filesystems {

  local module="cramfs"
  /sbin/modprobe -n -v ${module} | grep "install \+/bin/true" || return 
  lsmod | grepv "${module}" || return

}

function 20_Disable_Mounting_of_freevxfs_Filesystems {

  local module="freexvfs"
  /sbin/modprobe -n -v ${module} | grep "install \+/bin/true" || return 
  lsmod | grepv "${module}" || return

}

function 21_Disable_Mounting_of_jffs_Filesystems {

  local module="jffs2"
  /sbin/modprobe -n -v ${module} | grep "install \+/bin/true" || return 
  lsmod | grepv "${module}" || return

}

function 22_Disable_Mounting_of_hfs_Filesystems {

  local module="hfs"
  /sbin/modprobe -n -v ${module} | grep "install \+/bin/true" || return 
  lsmod | grepv "${module}" || return

}

function 23_Disable_Mounting_of_hfsplus_Filesystems {

  local module="hfsplus"
  /sbin/modprobe -n -v ${module} | grep "install \+/bin/true" || return 
  lsmod | grepv "${module}" || return

}

function 24_Disable_Mounting_of_squashfs_Filesystems {

  local module="squashfs"
  /sbin/modprobe -n -v ${module} | grep "install \+/bin/true" || return 
  lsmod | grepv "${module}" || return

}

function 25_Disable_Mounting_of_udf_Filesystems {

  local module="udf"
  /sbin/modprobe -n -v ${module} | grep "install \+/bin/true" || return 
  lsmod | grepv "${module}" || return

}

function 26_Disable_Automounting {

  /sbin/chkconfig --list autofs | grep -v "on" || return

}

function 27_Set_UserGroup_Owner_on_bootloader_config {

  local file="/boot/grub/menu.lst"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

}

function 28_Set_Permissions_on_bootloader_config {

  stat -L -c "%a" /boot/grub/menu.lst | grep '.00' || return

}

function 29_Set_Boot_Loader_Password {

  grep "^password" /boot/grub/menu.ls || return

}

function 30_Require_Authentication_for_Single_User_Mode {

  grep "~~:S:respawn" /etc/inittab || return

}

function 31_Disable_Interactive_Boot {

  grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot | grep no || return

}

function 32_Restrict_Core_Dumps {

  egrep "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "/etc/security/limits.conf" || return
  cut -d\# -f1 /etc//sbin/sysctl.conf | grep fs.suid_dumpable | cut -d= -f2 | tr -d '[[:space:]]' | grep '0' || return

}

function 33_Enable_XDNX_Support_on_bit_x86_Systems {

  dmesg | grep NX NX || return
 
}

function 34_Enable_Randomized_Virtual_Memory_Region_Placement {

  local flag="kernel.randomize_va_space"
  local value="2"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 35_Disable_Prelink {

  run "rpm -q prelink"
  local rpm="openldap2"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 36_Activate_AppArmor {

  apparmor_status || return

}

function 37_Ensure_NIS_Server_is_not_enabled {

  /sbin/chkconfig --list ypserv | grep -v "on" || return

}

function 38_Ensure_NIS_Client_is_not_installed {

  run "rpm -q ypbind"
  local rpm="openldap2"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 39_Ensure_rsh_server_is_not_enabled {

  /sbin/chkconfig --list rsh | grep -v "on" || return

}

function 40_Ensure_rsh_client_is_not_installed {

  local rpm="rsh"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 41_Ensure_talk_server_is_not_enabled {

  /sbin/chkconfig --list talk | grep -v "on" || return

}

function 42_Ensure_talk_client_is_not_installed {

  local rpm="talk"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 43_Ensure_telnet_server_is_not_enabled {

  /sbin/chkconfig --list telnet | grep -v "on" || return

}

function 44_Ensure_tftp_server_is_not_enabled { 

  /sbin/chkconfig --list tftp | grep -v "on" || return

}

function 45_Ensure_xinetd_is_not_enabled {

  /sbin/chkconfig --list xinetd | grep -v "on" || return

}

function 46_Ensure_chargen_udp_is_not_enabled {

  /sbin/chkconfig --list chargen-udp | grep -v "on" || return

}

function 47_Ensure_chargen_is_not_enabled {

  /sbin/chkconfig --list chargen | grep -v "on" || return

}

function 48_Ensure_daytime_udp_is_not_enabled {

  /sbin/chkconfig --list daytime-udp | grep -v "on" || return

}

function 49_Ensure_daytime_is_not_enabled {

  /sbin/chkconfig --list daytime | grep -v "on" || return

}

function 50_Ensure_echo_udp_is_not_enabled {

  /sbin/chkconfig --list echo-udp | grep -v "on" || return

}

function 51_Ensure_echo_is_not_enabled {

  /sbin/chkconfig --list echo | grep -v "on" || return

}

function 52_Ensure_discard_udp_is_not_enabled {

  /sbin/chkconfig --list discard-udp | grep -v "on" || return

}

function 53_Ensure_discard_is_not_enabled {

  /sbin/chkconfig --list discard | grep -v "on" || return

}

function 54_Ensure_time_udp_is_not_enabled {

  /sbin/chkconfig --list time-udp | grep -v "on" || return

}

function 55_Ensure_time_is_not_enabled {

  /sbin/chkconfig --list xorg-x11 | grep -v "on" || return

}

function 56_Ensure_X_Windows_is_not_installed {

  local rpm="xorg-x11"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 57_Ensure_Avahi_Server_is_not_enabled {

  /sbin/chkconfig --list avahi-daemon | grep -v "on" || return

}

function 58_Ensure_print_server_is_not_enabled {

  /sbin/chkconfig --list cups | grep -v "on" || return

}

function 59_Ensure_DHCP_Server_is_not_enabled {

  /sbin/chkconfig --list dhcpd | grep -v "on" || return

}

function 60_Configure_Network_Time_Protocol_NTP {

  cut -d\# -f1 /etc/ntp.conf | egrep "restrict{1}[[:space:]]+default{1}" /etc/ntp.conf | grep kod \
  | grep nomodify | grep notrap | grep nopeer | grep noquery || return

  cut -d\# -f1 /etc/ntp.conf | egrep "restrict{1}[[:space:]]+\-6{1}[[:space:]]+default" | grep kod \
  | grep nomodify | grep notrap | grep nopeer | grep noquery || return

  cut -d\# -f1 /etc/ntp.conf | egrep "^[[:space:]]*server" || return

  cut -d\# -f1 /etc/sysconfig/ntp | grep "OPTIONS=" | grep "ntp:ntp" || return

}

function 61_Ensure_LDAP_is_not_enabled {

  local rpm="openldap2"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 62_Ensure_NFS_and_RPC_are_not_enabled {

  /sbin/chkconfig --list nfs | grep -v "on" || return
  /sbin/chkconfig --list rpcbind | grep -v "on" || return

}

function 63_Ensure_DNS_Server_is_not_enabled {

  /sbin/chkconfig --list named | grep -v "on" || return

}

function 64_Ensure_FTP_Server_is_not_enabled {

  /sbin/chkconfig --list vsftpd | grep -v "on" || return

}

function 65_Ensure_HTTP_Server_is_not_enabled {

  /sbin/chkconfig --list apache2 | grep -v "on" || return

}

function 66_Ensure_IMAP_and_POP_server_is_not_enabled {

  /sbin/chkconfig --list cyrus | grep -v "on" || return

}

function 67_Ensure_Samba_is_not_enabled {

  /sbin/chkconfig --list smb | grep -v "on" || return

}

function 68_Ensure_HTTP_Proxy_Server_is_not_enabled {

  /sbin/chkconfig --list squid | grep -v "on" || return

}

function 69_Ensure_SNMP_Server_is_not_enabled {

  /sbin/chkconfig --list snmpd | grep -v "on" || return

}

function 70_Configure_Mail_Transfer_Agent_for_Local_Only_Mode {

  netstat_out="$(netstat -an | grep "LIST" | grep ":25[[:space:]]")"
  if [[ "$?" -eq 0 ]] ; then
    ip=$(echo ${netstat_out} | cut -d: -f1 | cut -d" " -f4)
    [[ "${ip}" = "127.0.0.1" ]] || return    
  fi
}

function 71_Ensure_rsync_service_is_not_enabled {

  /sbin/chkconfig --list rsyncd | grep -v "on" || return

}

function 72_Ensure_Biosdevname_is_not_enabled {

  local rpm="biosdevname"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 73_Disable_IP_Forwarding {

  local flag="net.ipv4.ip_forward"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 74_Disable_Send_Packet_Redirects {

  local flag="net.ipv4.conf.all.send_redirects"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

  local flag="net.ipv4.conf.default.send_redirects"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 75_Disable_Source_Routed_Packet_Acceptance {

  local flag="net.ipv4.conf.all.accept_source_route"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

  local flag="net.ipv4.conf.default.accept_source_routed"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 76_Disable_ICMP_Redirect_Acceptance {


  local flag="net.ipv4.conf.all.accept_redirects"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

  local flag="net.ipv4.conf.default.accept_redirecta"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 77_Disable_Secure_ICMP_Redirect_Acceptance {

  local flag="net.ipv4.conf.all.secure_redirects"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

  local flag="net.ipv4.conf.default.secure_redirects"
  local value="0"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 78_Log_Suspicious_Packets {


  local flag="net.ipv4.conf.all.log_martians"
  local value="1"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

  local flag="net.ipv4.conf.default.log_martians"
  local value="1"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 79_Enable_Ignore_Broadcast_Requests {

  local flag="net.ipv4.icmp_echo_ignore_broadcasts"
  local value="1"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 80_Enable_Bad_Error_Message_Protection {

  local flag="net.ipv4.icmp_ignore_bogus_error_responses"
  local value="1"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 81_Enable_RFC_recommended_Source_Route_Validation {

  local flag="net.ipv4.conf.all.rp_filter"
  local value="1"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

  local flag="net.ipv4.conf.default.rp_filter"
  local value="1"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 82_Enable_TCP_SYN_Cookies {

  local flag="net.ipv4.tcp_syncookies"
  local value="1"
  /sbin/sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep "${value}" || return

}

function 83_Disable_IPv6_Router_Advertisements {

  /sbin/sysctl net.ipv6.conf.all.accept_ra | grep 0 || return
  /sbin/sysctl net.ipv6.conf.default.accept_ra | grep 0 || return

}

function 84_Disable_IPv6_Redirect_Acceptance {

  /sbin/sysctl net.ipv6.conf.all.accept_redirects | grep 0 || return
  /sbin/sysctl net.ipv6.conf.default.accept_redirects | grep 0 || return

}

function 85_Disable_IPv6 {

  grep ipv6 /etc/modprobe.d/ipv6.conf | grep "disable=1" || return

}

function 86_Install_TCP_Wrappers {

  local rpm="openldap2"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 87_Create_etchostsallow {

  local file="/etc/hosts.allow"
  [[ -f "${file}" ]] || return

}

function 88_Verify_Permissions_on_etchostsallow {

  local file="/etc/hosts.allow"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/hosts.allow"
  local pattern="644"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 89_Create_etchostsdeny {

  local file="/etc/hosts.deny"
  [[ -f "${file}" ]] || return

}

function 90_Verify_Permissions_on_etchostsdeny {

  local file="/etc/hosts.deny"
  local pattern="644"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 91_Disable_DCCP {

  local protocol="dccp"
  local file="/etc/modprobe.d/CIS.conf"
  grep "install[[:space:]]${protocol}[[:space:]]/bin/true" ${file} || return

}

function 92_Disable_SCTP {

  local protocol="sctp"
  local file="/etc/modprobe.d/CIS.conf"
  grep "install[[:space:]]${protocol}[[:space:]]/bin/true" ${file} || return

}

function 93_Disable_RDS {

  local protocol="rds"
  local file="/etc/modprobe.d/CIS.conf"
  grep "install[[:space:]]${protocol}[[:space:]]/bin/true" ${file} || return

}

function 94_Disable_TIPC {

  local protocol="tipc"
  local file="/etc/modprobe.d/CIS.conf"
  grep "install[[:space:]]${protocol}[[:space:]]/bin/true" ${file} || return

}

function 95_Deactivate_Wireless_Interfaces {

  echo "#ifconfig -a"
  ifconfig -a

}

function 96_SuSEfirewall_is_active {

  /sbin/chkconfig --list SuSEfirewall2_setup | grep -v "off" || return

}

function 97_Limit_access_to_trusted_networks {

  echo "#grep "^FW_TRUSTED_NETS" /etc/sysconfig/SuSEfirewall2"
  grep "^FW_TRUSTED_NETS" /etc/sysconfig/SuSEfirewall2

}

function 98_Configure_Audit_Log_Storage_Size {

  cut -d\# -f1 /etc/audit/auditd.conf | egrep "max_log_file[[:space:]]|max_log_file=" || return

}

function 99_Disable_System_on_Audit_Log_Full {

  cut -d\# -f2 /etc/audit/auditd.conf | grep 'space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep 'email' || return
  cut -d\# -f2 /etc/audit/auditd.conf | grep 'action_mail_acct' | cut -d= -f2 | tr -d '[[:space:]]' | grep 'root' || return
  cut -d\# -f2 /etc/audit/auditd.conf | grep 'admin_space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep 'halt' || return

}

function 100_Keep_All_Auditing_Information {

  cut -d\# -f2 /etc/audit/auditd.conf | grep 'max_log_file_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep 'keep_logs' || return

}

function 101_Enable_auditd_Service {

  /sbin/chkconfig --list auditd | grep -v "off" || return

}

function 102_Enable_Auditing_for_Processes_That_Start_Prior_to_auditd {

  grep_grub="$(grep "^[[:space:]]*linux" /boot/grub/menu.lst | grep -v 'audit=1')"
  [[ -z "${grep_grub}" ]] || return

}

function 103_Record_Events_That_Modify_Date_and_Time_Information {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+stime" | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 $/etc/audit/audit.rules | egrep "\-k[[:space:]]+time-change" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/localtime" || return
}

function 104_Record_Events_That_Modify_UserGroup_Information {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/group" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/passwd" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/gshadow" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/shadow" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/security\/opasswd" || return

}

function 105_Record_Events_That_Modify_the_Systems_Network_Environment {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/issue" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/issue.net" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/hosts" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/sysconfig\/network" || return

}

function 106_Record_Events_That_Modify_the_Systems_Mandatory_Access_Controls {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+MAC-policy" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/selinux\/" || return

}

function 107_Collect_Login_and_Logout_Events {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/var\/log\/faillog" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/var\/log\/lastlog" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/var\/log\/tallylog" || return

}

function 108_Collect_Session_Initiation_Information {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+MAC-policy" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/selinux\/" || return

}

function 109_Collect_Discretionary_Access_Control_Permission_Modification_Events {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/var\/run\/utmp" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/var\/log\/wtmp" || return
  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/var\/log\/btmp" || return

}

function 110_Collect_Unsuccessful_Unauthorized_Access_Attempts_to_Files {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function 111_Collect_Use_of_Privileged_Commands {

  local priv_cmds
  priv_cmds="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f)"
  for cmd in ${priv_cmds} ; do
    cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+privileged" | egrep "\-F[[:space:]]+path=${cmd}" \
    | egrep "\-F[[:space:]]+perm=x" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
    | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  done

}

function 112_Collect_Successful_File_System_Mounts {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function 113_Collect_File_Deletion_Events_by_User {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function 115_Collect_System_Administrator_Actions_sudolog {

  echo "#scope /etc/audit/audit.rules"
  grep scope /etc/audit/audit.rules

}

function 114_Collect_Changes_to_System_Administration_Scope_sudoers {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+scope" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/etc\/sudoers" || return

}

function 116_Collect_Kernel_Module_Loading_and_Unloading {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "\-k[[:space:]]+actions" | egrep "\-p[[:space:]]+wa" \
  | egrep "\-w[[:space:]]+\/var\/log\/sudo.log" || return

}

function 117_Make_the_Audit_Configuration_Immutable {

  cut -d\# -f1 /etc/audit/audit.rules | egrep "^-e[[:space:]]+2" || return

}

function 118_Install_the_rsyslog_package {

  local rpm="openldap2"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 119_Ensure_the_rsyslog_Service_is_activated {

  grep SYSLOG_DAEMON /etc/sysconfig/syslog | grep rsylog || return

}

function 120_Configure_etcrsyslogconf {

  echo "#ls -l /var/log/"
  ls -l /var/log/

}

function 121_Create_and_Set_Permissions_on_rsyslog_Log_Files {

  echo "This item needs discussion with admin"

}

function 122_Configure_rsyslog_to_Send_Logs_to_a_Remote_Log_Host {

  grep "^*.*[^I][^I]*@" /etc/rsyslog.conf || return

}

function 123_Accept_Remote_rsyslog_Messages_Only_on_Designated_Log_Hosts {

  echo "#grep '$ModLoad imtcp.so' /etc/rsyslog.conf"
  grep '$ModLoad imtcp.so' /etc/rsyslog.conf

  echo
  echo

  echo "# grep '$InputTCPServerRun' /etc/rsyslog.conf"
  grep '$InputTCPServerRun' /etc/rsyslog.conf

}

function 124_Install_AIDE {

  local rpm="openldap2"
  rpm -q ${rpm} | grep "package ${rpm} is not installed" || return

}

function 125_Implement_Periodic_Execution_of_File_Integrity {

  crontab -u root -l | cut -d\# -f1 | grep "aide \+--check" || return

}

function 126_Configure_logrotate {

  [[ -f "${LOGR_SYSLOG}" ]] || return

  local timestamp
  timestamp=$(date '+%Y%m%d_%H%M%S')
  local tmp_data="/tmp/logrotate.tmp.${timestamp}"
  local file_list="/var/log/messages /var/log/allmessages /var/log/warn /var/logrotate.d/syslog"
  local line_num
  line_num=$(grep -n '{' "${LOGR_SYSLOG}" | cut -d: -f1)
  line_num=$((${line_num} - 1))
  head -${line_num} "${LOGR_SYSLOG}" > ${tmp_data}
  for file in ${file_list} ; do
    grep "${file}" ${tmp_data} || return
  done
  rm "${tmp_data}"

}

function 127_Enable_cron_Daemon {

  /sbin/chkconfig --list cron | grep -v "off" || return

}

function 128_Set_UserGroup_Owner_and_Permission_on_etccrontab {

  local file="/etc/crontab"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/crontab"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 129_Set_UserGroup_Owner_and_Permission_on_etccronhourly {

  local file="/etc/cron.hourly"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/cron.hourly"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 130_Set_UserGroup_Owner_and_Permission_on_etccrondaily {

  local file="/etc/cron.daily"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/cron.daily"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 131_Set_UserGroup_Owner_and_Permission_on_etccronweekly {

  local file="/etc/crontab"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/cron.weekly"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 132_Set_UserGroup_Owner_and_Permission_on_etccronmonthly {

  local file="/etc/cron.monthly"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/cron.monthly"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 133_Set_UserGroup_Owner_and_Permission_on_etccrond {

  local file="/etc/cron.d"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/cron.d"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 134_Restrict_atcron_to_Authorized_Users {

  [[ ! -f /etc/at.deny ]] || return 
  [[ ! -f /etc/cron.deny ]] || return 

  local file="/etc/cron.allow"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/cron.allow"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

  local file="/etc/at.allow"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/at.allow"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 135_Set_SSH_Protocol_to_ {

  local file="/etc/ssh/sshd_config" 
  local parameter="Protocol" 
  local value="2" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 136_Set_LogLevel_to_INFO {

  local file="/etc/ssh/sshd_config" 
  local parameter="LogLevel" 
  local value="INFO" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 137_Set_Permissions_on_etcsshsshd_config {

  local file="/etc/ssh/sshd_config"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

  local file="/etc/ssh/sshd_config"
  local pattern="600"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 138_Disable_SSH_X_Forwarding {

  local file="/etc/ssh/sshd_config" 
  local parameter="X11Forwarding" 
  local value="no" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 139_Set_SSH_MaxAuthTries_to__or_Less {

  local allowed_max="4"
  local actual_value
  actual_value=$(cut -d\# -f1 /etc/ssh/sshd_config | grep 'MaxAuthTries' | cut -d" " -f2)
  [[ ${actual_value} -le ${allowed_max} ]] || return 

}

function 140_Set_SSH_IgnoreRhosts_to_Yes {

  local file="/etc/ssh/sshd_config" 
  local parameter="IgnoreRhosts" 
  local value="yes" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 141_Set_SSH_HostbasedAuthentication_to_No {

  local file="/etc/ssh/sshd_config" 
  local parameter="HostbasedAuthentication" 
  local value="no" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 142_Disable_SSH_Root_Login {

  local file="/etc/ssh/sshd_config" 
  local parameter="PermitRootLogin" 
  local value="no" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 143_Set_SSH_PermitEmptyPasswords_to_No {

  local file="/etc/ssh/sshd_config" 
  local parameter="PermitEmptyPasswords" 
  local value="no" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 144_Do_Not_Allow_Users_to_Set_Environment_Options {

  local file="/etc/ssh/sshd_config" 
  local parameter="PermitUserEnvironment" 
  local value="no" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 145_Use_Only_Approved_Cipher_in_Counter_Mode {

  local file="/etc/ssh/sshd_config" 
  local parameter="Ciphers" 
  local value="aes128-ctr,aes192-ctr,aes256-ctr" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 146_Set_Idle_Timeout_Interval_for_User_Login {

  local file="/etc/ssh/sshd_config" 
  local parameter="ClientAliveInterval" 
  local value="300" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

  local file="/etc/ssh/sshd_config" 
  local parameter="ClientAliveCountMax" 
  local value="0" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 147_Limit_Access_via_SSH {

  local allow_users
  local allow_groups
  local deny_users
  local deny_users
  allow_users="$(cut -d\# -f1 /etc/ssh/sshd_config | grep "AllowUsers" | cut -d" " -f2)"
  allow_groups="$(cut -d\# -f1 /etc/ssh/sshd_config | grep "AllowGroups" | cut -d" " -f2)"
  deny_users="$(cut -d\# -f1 /etc/ssh/sshd_config | grep "DenyUsers" | cut -d" " -f2)"
  deny_groups="$(cut -d\# -f1 /etc/ssh/sshd_config | grep "DenyGroups" | cut -d" " -f2)"
  [[ -n "${allow_users}" ]] || return
  [[ -n "${allow_groups}" ]] || return
  [[ -n "${deny_users}" ]] || return
  [[ -n "${deny_groups}" ]] || return

}

function 148_Set_SSH_Banner {

  local file="/etc/ssh/sshd_config" 
  local parameter="Banner" 
  local value="/etc/issue.net" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 149_Set_Password_Creation_Requirement_Parameters_Using_pam_cracklib {

  echo "#grep pam_cracklib.so /etc/pam.d/common-password"
  grep pam_cracklib.so /etc/pam.d/common-password

}

function 150_Set_Lockout_for_Failed_Password_Attempts {

  echo "#grep "pam_tally2" /etc/pam.d/login"
  grep "pam_tally2" /etc/pam.d/login

}

function 151_Limit_Password_Reuse {

  pam-config -q --pwhistory  | grep 'pam_unix.so' | grep 'remember=5' || return

}

function 152_Restrict_root_Login_to_System_Console {

  echo "#cat /etc/securetty"
  cat /etc/securetty

}

function 153_Restrict_Access_to_the_su_Command {

  egrep "auth[[:space:]]+required" "/etc/pam.d/su" | grep 'pam_wheel.so' | grep 'use_uid' || return
  grep 'wheel' "/etc/group" | cut -d: -f4 | grep 'root' || return

}

function 154_Set_Password_Expiration_Days {

  local file="/etc/login.defs" 
  local parameter="PASS_MAX_DAYS" 
  local value="90" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 155_Set_Password_Change_Minimum_Number_of_Days {

  local file="/etc/login.defs" 
  local parameter="PASS_MIN_DAYS" 
  local value="7" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 156_Set_Password_Expiring_Warning_Days {

  local file="/etc/login.defs" 
  local parameter="PASS_WARN_AGE" 
  local value="7" 
  cut -d\# -f1 ${file} | egrep "^${parameter}[[:space:]]+${value}" || return

}

function 157_Disable_System_Accounts {

  local accounts 
  accounts="$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" \
&& $1!="halt" && $3<1000 && $7!="/sbin/nologin") {print}')"
  [[ -z "${accounts}" ]] || return

}

function 158_Set_Default_Group_for_root_Account {

  local gid1
  local gid2
  gid1="$(grep "^root:" "/etc/passwd" | cut -d: -f4)" 
  [[ "${gid1}" -eq 0 ]] || return
  gid2="$(id -g root)" 
  [[ "${gid2}" -eq 0 ]] || return

}

function 159_Set_Default_umask_for_Users {

  echo "#pam-config -q --umask session: umask=0077"
  pam-config -q --umask session: umask=0077
 

}

function 160_Lock_Inactive_User_Accounts {

  local days
  local inactive_threshold=35
  days="$(useradd -D | grep INACTIVE | cut -d= -f2)"
  [[ ${days} -ge ${inactive_threshold} ]] || return

}

function 161_Set_Warning_Banner_for_Standard_Login_Services {

  local motd
  local issue
  local issue_net
  motd="$(egrep '(\\v|\\r|\\m|\\s)' /etc/motd)"
  issue="$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net)"
  issue_net="$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net)"
  [[ -z "${motd}" ]] || return
  [[ -z "${issue}" ]] || return
  [[ -z "${issue_net}" ]] || return

}

function 162_Remove_OS_Information_from_Login_Warning_Banners {

  echo "#egrep '(\\v|\\r|\\m|\\s)' /etc/issue"
  egrep '(\\v|\\r|\\m|\\s)' /etc/issue

  echo
  echo "#egrep '(\\v|\\r|\\m|\\s)' /etc/motd"
  egrep '(\\v|\\r|\\m|\\s)' /etc/motd

  echo
  echo "#egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net"
  egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net

}

function 163_Set_Graphical_Warning_Banner {

  echo "#grep GreetString /usr/share/kde4/config/kdm/kdmrc"
  grep GreetString /usr/share/kde4/config/kdm/kdmrc

  echo 
  echo

  echo "#grep GreetString /usr/share/kde4/config/kdm/kdmrc"
  gconftool-2 -get /apps/gdm/simple-greeter/banner_message_text
   
}

function 164_Verify_System_File_Permissions {

  echo "#rpm -Va --nomtime --nosize --nomd5 --nolinkto"
  rpm -Va --nomtime --nosize --nomd5 --nolinkto

}

function 165_Verify_Permissions_on_etcpasswd {

  local file="/etc/passwd"
  local pattern="644"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 166_Verify_Permissions_on_etcshadow {

  local file="/etc/passwd"
  local pattern="0"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 167_Verify_Permissions_on_etcgroup {

  local file="/etc/group"
  local pattern="644"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

}

function 168_Verify_UserGroup_Ownership_on_etcpasswd {

  local file="/etc/passwd"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

}

function 169_Verify_UserGroup_Ownership_on_etcshadow {

  local file="/etc/shadow"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

}

function 170_Verify_UserGroup_Ownership_on_etcgroup {

  local file="/etc/group"
  stat -L -c "%u %g" ${file} | grep '0 0' || return

}

function 171_Find_World_Writable_Files {

  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002)"
  [[ -z "${dirs}" ]] || return 

}

function 172_Find_Un_owned_Files_and_Directories {

  local uo_files
  uo_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
  [[ -z "${uo_files}" ]] || return

}

function 173_Find_Un_grouped_Files_and_Directories {

  local ug_files
  ug_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
  [[ -z "${ug_files}" ]] || return

}

function 174_Find_SUID_System_Executables {

  local suid_exes
  suid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for suid_exe in ${suid_exes}
  do
    rpm_out="$(rpm -V $(rpm -qf ${suid_exe}))"
    [[ -z "${rpm_out}" ]] || return
  done

}

function 175_Find_SGID_System_Executables {

  local ug_files
  ug_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print)"
  [[ -z "${ug_files}" ]] || return

}

function 176_Ensure_Password_Fields_are_Not_Empty {

  local shadow_out
  shadow_out="$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)"
  [[ -z "${shadow_out}" ]] || return

}

function 177_Verify_No_Legacy_Entries_Exist_in_etcpasswd_File {

  local file="/etc/passwd"
  local grep_out
  grep_out="$(grep '^+:' ${file})"
  [[ -z "${grep_out}" ]] || return

}

function 178_Verify_No_Legacy_Entries_Exist_in_etcshadow_File {

  local file="/etc/shadow"
  local grep_out
  grep_out="$(grep '^+:' ${file})"
  [[ -z "${grep_out}" ]] || return

}

function 179_Verify_No_Legacy_Entries_Exist_in_etcgroup_File {

  local file="/etc/group"
  local grep_out
  grep_out="$(grep '^+:' ${file})"
  [[ -z "${grep_out}" ]] || return

}

function 180_Verify_No_UID_0_Accounts_Exist_Other_Than_root {

  local grep_passwd
  grep_passwd="$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)"
  [[ "${grep_passwd}" = "root" ]] || return 

}

function is_group_writable {

  local ls_output="${1}"
  [[ "${ls_output:5:1}" = "w" ]] || return

}

function 181_Ensure_root_PATH_Integrity {

  local grep=/bin/grep
  local sed=/bin/sed
  path_grep="$(echo ${PATH} | ${grep} '::')"
  [[ -z "${path_grep}" ]] || return 

  path_grep="$(echo ${PATH} | ${grep} :$)"
  [[ -z "${path_grep}" ]] || return 

  path_dirs="$(echo $PATH | ${sed} -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')"
  for dir in ${path_dirs} ; do

    [[ "${dir}" != "." ]] || return


    [[ -d "${dir}" ]] || return

    local ls_out
    ls_out="$(ls -ldH ${dir})" 
    if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi


    dir_own="$(echo ${ls_out} | awk '{print $3}')"
    [[ "${dir_own}" = "root" ]] || return
  done

}

function 182_Check_Permissions_on_User_Home_Directories {

  dirs="$(grep -v 'root|halt|sync|shutdown' /etc/passwd | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  [[ -z "${dirs}" ]] && return
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    local ls_out
    ls_out="$(ls -ldH ${dir})"
    if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_readable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_executable ${ls_out} ; then return 1 ; else return 0 ; fi
  done

}

function 183_Check_User_Dot_File_Permissions {

  dirs="$(grep -v 'root|halt|sync|shutdown' /etc/passwd | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    for file in ${dir}/.[A-Za-z0-9]* ; do
      if [[ ! -h "${file}" && -f "${file}" ]] ; then
        local ls_out
        ls_out="$(ls -ldH ${dir})"
        if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi 
        if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
      fi 
    done
  done

}

function 184_Check_Permissions_on_User_netrc_Files {

  dirs="$(grep -v 'root|halt|sync|shutdown' /etc/passwd | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    for file in ${dir}/.netrc ; do
      if [[ ! -h "${file}" && -f "${file}" ]] ; then
        local ls_out
        ls_out="$(ls -ldH ${dir})"
        if is_group_readable ${ls_out} ; then return 1 ; else return 0 ; fi 
        if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
        if is_group_executable ${ls_out} ; then return 1 ; else return 0 ; fi
        if is_other_readable ${ls_out} ; then return 1 ; else return 0 ; fi 
        if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi
        if is_other_executable ${ls_out} ; then return 1 ; else return 0 ; fi
      fi 
    done
  done

}

function 185_Check_for_Presence_of_User_rhosts_Files {

  dirs="$(grep -v 'root|halt|sync|shutdown' /etc/passwd | awk -F: '($7 != "/sbin/nologin") { print $6 }')"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    local file="${dir}/.rhosts"
    if [[ ! -h "${file}" && -f "${file}" ]] ; then
      return 1
    else
      return 0
    fi
  done

}

function 186_Check_Groups_in_etcpasswd {

  group_ids="$(cut -s -d: -f4 /etc/passwd | sort -u)"
  for group_id in ${group_ids} ; do
    grep -q -P "^.*?:x:${group_id}:" /etc/group || return
  done

}

function 187_Check_That_Users_Are_Assigned_Valid_Home_Directories {


  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
      return 1 
    fi
  done < <(awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd)

}

function 188_Check_User_Home_Directory_Ownership {

  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
      local owner
      owner="$(stat -L -c "%U" "${dir}")"
      [[ "${owner}" = "${user}" ]] || return
    fi
  done < <(awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd)
 
}

function 189_Check_for_Duplicate_UIDs {

  local num_of_uids
  local uniq_num_of_uids
  num_of_uids="$(cut -f3 -d":" /etc/passwd | wc -l)"
  uniq_num_of_uids="$(cut -f3 -d":" /etc/passwd | sort -n | uniq | wc -l)" 
  [[ "${num_of_uids}" -eq "${uniq_num_of_uids}" ]] || return

}

function 190_Check_for_Duplicate_GIDs {

  local num_of_gids
  local uniq_num_of_gids
  num_of_gids="$(cut -f3 -d":" /etc/group | wc -l)"
  uniq_num_of_gids="$(cut -f3 -d":" /etc/group | sort -n | uniq | wc -l)" 
  [[ "${num_of_gids}" -eq "${uniq_num_of_gids}" ]] || return

}

function 191_Check_for_Duplicate_User_Names {

  local num_of_usernames
  local num_of_uniq_usernames
  num_of_usernames="$(cut -f1 -d":" /etc/passwd | wc -l)"
  num_of_uniq_usernames="$(cut -f1 -d":" /etc/passwd | sort | uniq | wc -l)" 
  [[ "${num_of_usernames}" -eq "${num_of_uniq_usernames}" ]] || return

}

function 192_Check_for_Duplicate_Group_Names {

  local num_of_groupnames
  local num_of_uniq_groupnames
  num_of_groupnames="$(cut -f1 -d":" /etc/group | wc -l)"
  num_of_uniq_groupnames="$(cut -f1 -d":" /etc/group | sort | uniq | wc -l)" 
  [[ "${num_of_groupnames}" -eq "${num_of_uniq_groupnames}" ]] || return

}

function 193_Check_for_Presence_of_User_netrc_Files {

  local dirs
  dirs="$(cut -d: -f6 /etc/passwd)" 
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.netrc" && -f "${dir}/.netrc" ]] ; then
      return 1 
    fi
  done

}

function 194_Check_for_Presence_of_User_forward_Files {

  local dirs
  dirs="$(cut -d: -f6 /etc/passwd)" 
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.forward" && -f "${dir}/.forward" ]] ; then
      return 1 
    fi
  done

}

function 195_Ensure_shadow_group_is_empty {

  grep ^shadow /etc/group | grep -v ":" || return
  sh rules/195.sh | grep -v ":" || return

}






function suse_en {

header

main_auto 1_Install_Updates_Patches_and_Additional_Security_Software
main_auto 2_Create_Separate_Partition_for_tmp
main_auto 3_Set_nodev_option_for_tmp_Partition
main_auto 4_Set_nosuid_option_for_tmp_Partition
main_auto 5_Set_noexec_option_for_tmp_Partition
main_auto 6_Create_Separate_Partition_for_var
main_auto 7_Bind_Mount_the_vartmp_directory_to_tmp
main_auto 8_Create_Separate_Partition_for_var_log
main_auto 9_Create_Separate_Partition_for_varlog_audit
main_auto 10_Create_Separate_Partition_for_home
main_auto 11_Add_nodev_Option_to_home
main_manual 12_Add_nodev_Option_to_Removable_Media_Partitions
main_manual 13_Add_noexec_Option_to_Removable_Media_Partitions
main_manual 14_Add_nosuid_Option_to_Removable_Media_Partitions
main_auto 15_Add_nodev_Option_to_devshm_Partition
main_auto 16_Add_nosuid_Option_to_devshm_Partition
main_auto 17_Add_noexec_Option_to_devshm_Partition
main_auto 18_Set_Sticky_Bit_on_All_World_Writable_Directories
main_auto 19_Disable_Mounting_of_cramfs_Filesystems
main_auto 20_Disable_Mounting_of_freevxfs_Filesystems
main_auto 21_Disable_Mounting_of_jffs_Filesystems
main_auto 22_Disable_Mounting_of_hfs_Filesystems
main_auto 23_Disable_Mounting_of_hfsplus_Filesystems
main_auto 24_Disable_Mounting_of_squashfs_Filesystems
main_auto 25_Disable_Mounting_of_udf_Filesystems
main_auto 26_Disable_Automounting
main_auto 27_Set_UserGroup_Owner_on_bootloader_config
main_auto 28_Set_Permissions_on_bootloader_config
main_auto 29_Set_Boot_Loader_Password
main_auto 30_Require_Authentication_for_Single_User_Mode
main_auto 31_Disable_Interactive_Boot
main_auto 32_Restrict_Core_Dumps
main_auto 33_Enable_XDNX_Support_on_bit_x86_Systems
main_auto 34_Enable_Randomized_Virtual_Memory_Region_Placement
main_auto 35_Disable_Prelink
main_auto 36_Activate_AppArmor
main_auto 37_Ensure_NIS_Server_is_not_enabled
main_auto 38_Ensure_NIS_Client_is_not_installed
main_auto 39_Ensure_rsh_server_is_not_enabled
main_auto 40_Ensure_rsh_client_is_not_installed
main_auto 41_Ensure_talk_server_is_not_enabled
main_auto 42_Ensure_talk_client_is_not_installed
main_auto 43_Ensure_telnet_server_is_not_enabled
main_auto 44_Ensure_tftp_server_is_not_enabled
main_auto 45_Ensure_xinetd_is_not_enabled
main_auto 46_Ensure_chargen_udp_is_not_enabled
main_auto 47_Ensure_chargen_is_not_enabled
main_auto 48_Ensure_daytime_udp_is_not_enabled
main_auto 49_Ensure_daytime_is_not_enabled
main_auto 50_Ensure_echo_udp_is_not_enabled
main_auto 51_Ensure_echo_is_not_enabled
main_auto 52_Ensure_discard_udp_is_not_enabled
main_auto 53_Ensure_discard_is_not_enabled
main_auto 54_Ensure_time_udp_is_not_enabled
main_auto 55_Ensure_time_is_not_enabled
main_auto 56_Ensure_X_Windows_is_not_installed
main_auto 57_Ensure_Avahi_Server_is_not_enabled
main_auto 58_Ensure_print_server_is_not_enabled
main_auto 59_Ensure_DHCP_Server_is_not_enabled
main_auto 60_Configure_Network_Time_Protocol_NTP
main_auto 61_Ensure_LDAP_is_not_enabled
main_auto 62_Ensure_NFS_and_RPC_are_not_enabled
main_auto 63_Ensure_DNS_Server_is_not_enabled
main_auto 64_Ensure_FTP_Server_is_not_enabled
main_auto 65_Ensure_HTTP_Server_is_not_enabled
main_auto 66_Ensure_IMAP_and_POP_server_is_not_enabled
main_auto 67_Ensure_Samba_is_not_enabled
main_auto 68_Ensure_HTTP_Proxy_Server_is_not_enabled
main_auto 69_Ensure_SNMP_Server_is_not_enabled
main_auto 70_Configure_Mail_Transfer_Agent_for_Local_Only_Mode
main_auto 71_Ensure_rsync_service_is_not_enabled
main_auto 72_Ensure_Biosdevname_is_not_enabled
main_auto 73_Disable_IP_Forwarding
main_auto 74_Disable_Send_Packet_Redirects
main_auto 75_Disable_Source_Routed_Packet_Acceptance
main_auto 76_Disable_ICMP_Redirect_Acceptance
main_auto 77_Disable_Secure_ICMP_Redirect_Acceptance
main_auto 78_Log_Suspicious_Packets
main_auto 79_Enable_Ignore_Broadcast_Requests
main_auto 80_Enable_Bad_Error_Message_Protection
main_auto 81_Enable_RFC_recommended_Source_Route_Validation
main_auto 82_Enable_TCP_SYN_Cookies
main_auto 83_Disable_IPv6_Router_Advertisements
main_auto 84_Disable_IPv6_Redirect_Acceptance
main_auto 85_Disable_IPv6
main_auto 86_Install_TCP_Wrappers
main_auto 87_Create_etchostsallow
main_auto 88_Verify_Permissions_on_etchostsallow
main_auto 89_Create_etchostsdeny
main_auto 90_Verify_Permissions_on_etchostsdeny
main_auto 91_Disable_DCCP
main_auto 92_Disable_SCTP
main_auto 93_Disable_RDS
main_auto 94_Disable_TIPC
main_manual 95_Deactivate_Wireless_Interfaces
main_auto 96_SuSEfirewall_is_active
main_manual 97_Limit_access_to_trusted_networks
main_auto 98_Configure_Audit_Log_Storage_Size
main_auto 99_Disable_System_on_Audit_Log_Full
main_auto 100_Keep_All_Auditing_Information
main_auto 101_Enable_auditd_Service
main_auto 102_Enable_Auditing_for_Processes_That_Start_Prior_to_auditd
main_auto 103_Record_Events_That_Modify_Date_and_Time_Information
main_auto 104_Record_Events_That_Modify_UserGroup_Information
main_auto 105_Record_Events_That_Modify_the_Systems_Network_Environment
main_auto 106_Record_Events_That_Modify_the_Systems_Mandatory_Access_Controls
main_auto 107_Collect_Login_and_Logout_Events
main_auto 108_Collect_Session_Initiation_Information
main_auto 109_Collect_Discretionary_Access_Control_Permission_Modification_Events
main_auto 110_Collect_Unsuccessful_Unauthorized_Access_Attempts_to_Files
main_auto 111_Collect_Use_of_Privileged_Commands
main_auto 112_Collect_Successful_File_System_Mounts 
main_auto 113_Collect_File_Deletion_Events_by_User
main_auto 114_Collect_Changes_to_System_Administration_Scope_sudoers
main_manual 115_Collect_System_Administrator_Actions_sudolog
main_auto 116_Collect_Kernel_Module_Loading_and_Unloading
main_auto 117_Make_the_Audit_Configuration_Immutable
main_auto 118_Install_the_rsyslog_package
main_auto 119_Ensure_the_rsyslog_Service_is_activated
main_manual 120_Configure_etcrsyslogconf
main_auto 121_Create_and_Set_Permissions_on_rsyslog_Log_Files
main_auto 122_Configure_rsyslog_to_Send_Logs_to_a_Remote_Log_Host
main_manual 123_Accept_Remote_rsyslog_Messages_Only_on_Designated_Log_Hosts
main_auto 124_Install_AIDE
main_auto 125_Implement_Periodic_Execution_of_File_Integrity
main_auto 126_Configure_logrotate
main_auto 127_Enable_cron_Daemon
main_auto 128_Set_UserGroup_Owner_and_Permission_on_etccrontab
main_auto 129_Set_UserGroup_Owner_and_Permission_on_etccronhourly
main_auto 130_Set_UserGroup_Owner_and_Permission_on_etccrondaily
main_auto 131_Set_UserGroup_Owner_and_Permission_on_etccronweekly
main_auto 132_Set_UserGroup_Owner_and_Permission_on_etccronmonthly
main_auto 133_Set_UserGroup_Owner_and_Permission_on_etccrond
main_auto 134_Restrict_atcron_to_Authorized_Users
main_auto 135_Set_SSH_Protocol_to_
main_auto 136_Set_LogLevel_to_INFO
main_auto 137_Set_Permissions_on_etcsshsshd_config
main_auto 138_Disable_SSH_X_Forwarding
main_auto 139_Set_SSH_MaxAuthTries_to__or_Less
main_auto 140_Set_SSH_IgnoreRhosts_to_Yes
main_auto 141_Set_SSH_HostbasedAuthentication_to_No
main_auto 142_Disable_SSH_Root_Login 
main_auto 143_Set_SSH_PermitEmptyPasswords_to_No
main_auto 144_Do_Not_Allow_Users_to_Set_Environment_Options
main_auto 145_Use_Only_Approved_Cipher_in_Counter_Mode
main_auto 146_Set_Idle_Timeout_Interval_for_User_Login
main_auto 147_Limit_Access_via_SSH
main_auto 148_Set_SSH_Banner
main_manual 149_Set_Password_Creation_Requirement_Parameters_Using_pam_cracklib
main_manual 150_Set_Lockout_for_Failed_Password_Attempts
main_auto 151_Limit_Password_Reuse
main_manual 152_Restrict_root_Login_to_System_Console
main_auto 153_Restrict_Access_to_the_su_Command
main_auto 154_Set_Password_Expiration_Days
main_auto 155_Set_Password_Change_Minimum_Number_of_Days
main_auto 156_Set_Password_Expiring_Warning_Days
main_auto 157_Disable_System_Accounts
main_auto 158_Set_Default_Group_for_root_Account
main_manual 159_Set_Default_umask_for_Users
main_auto 160_Lock_Inactive_User_Accounts
main_auto 161_Set_Warning_Banner_for_Standard_Login_Services
main_manual 162_Remove_OS_Information_from_Login_Warning_Banners
main_manual 163_Set_Graphical_Warning_Banner
main_manual 164_Verify_System_File_Permissions
main_auto 165_Verify_Permissions_on_etcpasswd
main_auto 166_Verify_Permissions_on_etcshadow
main_auto 167_Verify_Permissions_on_etcgroup
main_auto 168_Verify_UserGroup_Ownership_on_etcpasswd
main_auto 169_Verify_UserGroup_Ownership_on_etcshadow
main_auto 170_Verify_UserGroup_Ownership_on_etcgroup
main_auto 171_Find_World_Writable_Files
main_auto 172_Find_Un_owned_Files_and_Directories
main_auto 173_Find_Un_grouped_Files_and_Directories
main_auto 174_Find_SUID_System_Executables
main_auto 175_Find_SGID_System_Executables
main_auto 176_Ensure_Password_Fields_are_Not_Empty
main_auto 177_Verify_No_Legacy_Entries_Exist_in_etcpasswd_File
main_auto 178_Verify_No_Legacy_Entries_Exist_in_etcshadow_File
main_auto 179_Verify_No_Legacy_Entries_Exist_in_etcgroup_File
main_auto 180_Verify_No_UID_0_Accounts_Exist_Other_Than_root
main_auto 181_Ensure_root_PATH_Integrity
main_auto 182_Check_Permissions_on_User_Home_Directories
main_auto 183_Check_User_Dot_File_Permissions
main_auto 184_Check_Permissions_on_User_netrc_Files
main_auto 185_Check_for_Presence_of_User_rhosts_Files
main_auto 186_Check_Groups_in_etcpasswd
main_auto 187_Check_That_Users_Are_Assigned_Valid_Home_Directories
main_auto 188_Check_User_Home_Directory_Ownership
main_auto 189_Check_for_Duplicate_UIDs
main_auto 190_Check_for_Duplicate_GIDs
main_auto 191_Check_for_Duplicate_User_Names
main_auto 192_Check_for_Duplicate_Group_Names
main_auto 193_Check_for_Presence_of_User_netrc_Files
main_auto 194_Check_for_Presence_of_User_forward_Files
main_auto 195_Ensure_shadow_group_is_empty

}



filename=suse-checklists-$( date +"%m-%d-%y-%H-%M" )

suse_en &> $filename.txt
suse_en

echo
echo
echo "*Report : $filename.txt"
echo
