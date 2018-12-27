#!/bin/bash
function header {

echo
echo 
echo "                         Audit Script                          "
echo "          Oracle Database 11g R2 - Security Auditor            "
echo "                         Hamed Izadi (@hezd)                   "
echo
echo "###############################################################"
echo "###############################################################"
echo

}

#/opt/oracle/product/11gR2/db/bin

# $ lsnrctl start
# $ dbstart
# $ sqlplus '/ as sysdba'
# SQL> startup

function main_manual {

  func_name=$1
  echo "||| ${func_name}"
  echo
  shift
  args=$@
  ${func_name} ${args}
  line

}

function line {
  echo 
  tput setaf 7; echo "######################## MANUAL CHECK #########################"
  echo
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

function sql_q {

  local sql_s=$1

  RETVAL=$(sqlplus -s '/ as sysdba' << EOF
			 SET TERMOUT OFF
			 SET HEADING ON
			 SET PAGESIZE 50000
			 SET LINESIZE 100
			 SET TRIMSPOOL on
			 SET WRAP OFF
			 SET FEEDBACK ON
			 SET ECHO OFF
			 SET COLSEP |
			 SET serveroutput on
             ${sql_s}
             exit;
             EOF)
  tput setaf 4; echo "$RETVAL"; tput setaf 7;
  # if [ -z "$RETVAL" ]; then
  # 	echo "No rows returned"
  # else
  #   echo $RETVAL
  # fi

}


function 1_Ensure_the_Appropriate_VersionPatches_for_Oracle_Software_Is_Installed {

sql_q "SELECT PRODUCT, VERSION FROM PRODUCT_COMPONENT_VERSION WHERE PRODUCT LIKE '%Database%' AND VERSION LIKE '11.2.0.4%';"
echo
echo
sql_q "SELECT ACTION, VERSION,ID FROM DBA_REGISTRY_HISTORY WHERE TO_DATE(TRIM(TO_CHAR(ID)), 'YYMMDD') > SYSDATE-90 AND ID > 160000;"

}

function 2_Ensure_All_Default_Passwords_Are_Changed {

sql_q "SELECT USERNAME FROM DBA_USERS_WITH_DEFPWD WHERE USERNAME NOT LIKE '%XS$NULL%';"


}

function 3_Ensure_All_Sample_Data_And_Users_Have_Been_Removed {

sql_q "SELECT USERNAME FROM ALL_USERS WHERE USERNAME IN ('BI','HR','IX','OE','PM','SCOTT','SH');" | grep "no rows selected" || return

}

function 4_Ensure_SECURE_CONTROL_ltlistener_namegt_Is_Set_In_listenerora {

echo "*To audit this recommendation follow these steps:	

	Open the $ORACLE_HOME/network/admin/listener.ora file 

	Ensure that each defined listener as an associated SECURE_CONTROL_<listener_name> directive."

}

function 5_Ensure_extproc_Is_Not_Present_in_listenerora {

extproc="$(grep -i extproc $ORACLE_HOME/network/admin/listener.ora)"
[[ -z "${extproc}" ]] || return

}

function 6_Ensure_ADMIN_RESTRICTIONS_ltlistener_namegt_Is_Set_to_ON {

grep -i admin_restrictions $ORACLE_HOME/network/admin/listener.ora  | grep -i "on" || return

}

function 7_Ensure_SECURE_REGISTER_ltlistener_namegt_Is_Set_to_TCPS_or_IPC {

grep -i SECURE_REGISTER $ORACLE_HOME/network/admin/listener.ora  | grep -E "TCPS|IPC" || return

}

function 8_Ensure_AUDIT_SYS_OPERATIONS_Is_Set_to_TRUE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME) = 'AUDIT_SYS_OPERATIONS';" | grep "TRUE" || return

}

function 9_Ensure_AUDIT_TRAIL_Is_Set_to_OS_DBEXTENDED_or_XMLEXTENDED {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='AUDIT_TRAIL';" | grep -E "DB|XML|OS" || return

}

function 10_Ensure_GLOBAL_NAMES_Is_Set_to_TRUE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='GLOBAL_NAMES';" | grep "TRUE" || return

}

function 11_Ensure_LOCAL_LISTENER_Is_Set_Appropriately {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='LOCAL_LISTENER';"  | grep "ADDRESS=(PROTOCOL=IPC)(KEY=REGISTER" || return

}

function 12_Ensure_O7_DICTIONARY_ACCESSIBILITY_Is_Set_to_FALSE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='O7_DICTIONARY_ACCESSIBILITY';" | grep "FALSE" || return

}

function 13_Ensure_OS_ROLES_Is_Set_to_FALSE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='OS_ROLES';" | grep "FALSE" || return

}

function 14_Ensure_REMOTE_LISTENER_Is_Empty {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='REMOTE_LISTENER';" | grep "1 row selected" || return

}

function 15_Ensure_REMOTE_LOGIN_PASSWORDFILE_Is_Set_to_NONE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='REMOTE_LOGIN_PASSWORDFILE';" | grep "NONE" || return

}

function 16_Ensure_REMOTE_OS_AUTHENT_Is_Set_to_FALSE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='REMOTE_OS_AUTHENT';" | grep "FALSE" || return

}

function 17_Ensure_REMOTE_OS_ROLES_Is_Set_to_FALSE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='REMOTE_OS_ROLES';" | grep "FALSE" || return

}

function 18_Ensure_UTIL_FILE_DIR_Is_Empty {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='UTIL_FILE_DIR';" | grep "no rows selected" || return

}

function 19_Ensure_SEC_CASE_SENSITIVE_LOGON_Is_Set_to_TRUE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='SEC_CASE_SENSITIVE_LOGON';" | grep "TRUE" || return

}

function 20_Ensure_SEC_MAX_FAILED_LOGIN_ATTEMPTS_Is_Set_to_10 {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='SEC_MAX_FAILED_LOGIN_ATTEMPTS';" | grep "10" || return

}

function 21_Ensure_SEC_PROTOCOL_ERROR_FURTHER_ACTION_Is_Set_to_DELAY3_or_DROP3 {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_FURTHER_ACTION';" | grep -E "DELAY,3|DROP,3" || return

}

function 22_Ensure_SEC_PROTOCOL_ERROR_TRACE_ACTION_Is_Set_to_LOG {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_TRACE_ACTION';" | grep "LOG" || return

}

function 23_Ensure_SEC_RETURN_SERVER_RELEASE_BANNER_Is_Set_to_FALSE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='SEC_RETURN_SERVER_RELEASE_BANNER';" | grep "FALSE" || return

}

function 24_Ensure_SQL92_SECURITY_Is_Set_to_TRUE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='SQL92_SECURITY';" | grep "TRUE" || return

}

function 25_Ensure_TRACE_FILES_PUBLIC_Is_Set_to_FALSE {

sql_q "SELECT VALUE FROM V\$PARAMETER WHERE NAME='_trace_files_public';"  | grep "FALSE" || return

}

function 26_Ensure_RESOURCE_LIMIT_Is_Set_to_TRUE {

sql_q "SELECT UPPER(VALUE) FROM V\$PARAMETER WHERE UPPER(NAME)='RESOURCE_LIMIT';" | grep "TRUE" || return

}

function 27_Ensure_FAILED_LOGIN_ATTEMPTS_Is_Less_than_or_Equal_to_5 {

sql_q "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS' AND ( LIMIT = 'DEFAULT' OR LIMIT = 'UNLIMITED' OR LIMIT > 5 );" | grep "no rows selected" || return

}

function 28_Ensure_PASSWORD_LOCK_TIME_Is_Greater_than_or_Equal_to_1 {

sql_q "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_LOCK_TIME' AND ( LIMIT = 'DEFAULT' OR LIMIT = 'UNLIMITED' OR LIMIT < 1 );" | grep "no rows selected" || return

}

function 29_Ensure_PASSWORD_LIFE_TIME_Is_Less_than_or_Equal_to_90 {

sql_q "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_LIFE_TIME' AND ( LIMIT = 'DEFAULT' OR LIMIT = 'UNLIMITED' OR LIMIT > 90 );" | grep "no rows selected" || return

}

function 30_Ensure_PASSWORD_REUSE_MAX_Is_Greater_than_or_Equal_to_20 {

sql_q "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_REUSE_MAX' AND ( LIMIT = 'DEFAULT' OR LIMIT = 'UNLIMITED' OR LIMIT < 20 );" | grep "no rows selected" || return

}

function 31_Ensure_PASSWORD_REUSE_TIME_Is_Greater_than_or_Equal_to_365 {

sql_q "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_REUSE_TIME' AND ( LIMIT = 'DEFAULT' OR LIMIT = 'UNLIMITED' OR LIMIT < 365 );" | grep "no rows selected" || return

}

function 32_Ensure_PASSWORD_GRACE_TIME_Is_Less_than_or_Equal_to_5 {

sql_q "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_GRACE_TIME' AND ( LIMIT = 'DEFAULT' OR LIMIT = 'UNLIMITED' OR LIMIT > 5 );" | grep "no rows selected" || return

}

function 33_Ensure_DBA_USERSPASSWORD_Is_Not_Set_to_EXTERNAL_for_Any_User {

sql_q "SELECT USERNAME FROM DBA_USERS WHERE PASSWORD='EXTERNAL';" | grep "no rows selected" || return

}

function 34_Ensure_PASSWORD_VERIFY_FUNCTION_Is_Set_for_All_Profiles {

sql_q "SELECT PROFILE, RESOURCE_NAME FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_VERIFY_FUNCTION' AND (LIMIT = 'DEFAULT' OR LIMIT = 'NULL');" | grep "no rows selected" || return

}

function 35_Ensure_SESSIONS_PER_USER_Is_Less_than_or_Equal_to_10 {

sql_q "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='SESSIONS_PER_USER' AND ( LIMIT = 'DEFAULT' OR LIMIT = 'UNLIMITED' OR LIMIT > 10 );" | grep "no rows selected" || return

}

function 36_Ensure_No_Users_Are_Assigned_the_DEFAULT_Profile {

sql_q "SELECT USERNAME FROM DBA_USERS WHERE PROFILE='DEFAULT' AND ACCOUNT_STATUS='OPEN' AND USERNAME NOT IN ('ANONYMOUS', 'CTXSYS', 'DBSNMP', 'EXFSYS', 'LBACSYS', 'MDSYS', 'MGMT_VIEW','OLAPSYS','OWBSYS', 'ORDPLUGINS', 'ORDSYS', 'OUTLN', 'SI_INFORMTN_SCHEMA','SYS', 'SYSMAN', 'SYSTEM', 'TSMSYS', 'WK_TEST', 'WKSYS', 'WKPROXY', 'WMSYS', 'XDB', 'CISSCAN');" | grep "no rows selected" || return

}

function 37_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_ADVISOR {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_ADVISOR';" | grep "no rows selected" || return

}

function 38_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_CRYPTO {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND TABLE_NAME='DBMS_CRYPTO';" | grep "no rows selected" || return

}

function 39_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_JAVA {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_JAVA';" | grep "no rows selected" || return

}

function 40_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_JAVA_TEST {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_JAVA_TEST';" | grep "no rows selected" || return

}

function 41_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_JOB {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_JOB';" | grep "no rows selected" || return

}

function 42_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_LDAP {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_LDAP';" | grep "no rows selected" || return

}

function 43_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_LOB {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_LOB';" | grep "no rows selected" || return

}

function 44_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_OBFUSCATION_TOOLKIT {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_OBFUSCATION_TOOLKIT';" | grep "no rows selected" || return

}

function 45_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_RANDOM {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_RANDOM';" | grep "no rows selected" || return

}

function 46_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_SCHEDULER {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_SCHEDULER';" | grep "no rows selected" || return

}

function 47_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_SQL {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_SQL';" | grep "no rows selected" || return

}

function 48_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_XMLGEN {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_XMLGEN';" | grep "no rows selected" || return

}

function 49_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_XMLQUERY {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_XMLQUERY';" | grep "no rows selected" || return

}

function 50_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_FILE {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_FILE';" | grep "no rows selected" || return

}

function 51_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_INADDR {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_INADDR';" | grep "no rows selected" || return

}

function 52_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_TCP {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_TCP';" | grep "no rows selected" || return

}

function 53_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_MAIL {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_MAIL';" | grep "no rows selected" || return

}

function 54_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_SMTP {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_SMTP';" | grep "no rows selected" || return

}

function 55_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_DBWS {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_DBWS';" | grep "no rows selected" || return

}

function 56_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_ORAMTS {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_ORAMTS';" | grep "no rows selected" || return

}

function 57_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_HTTP {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='UTL_HTTP';" | grep "no rows selected" || return

}

function 58_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_HTTPURITYPE {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='HTTPURITYPE';" | grep "no rows selected" || return

}

function 59_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_SYS_SQL {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_SYS_SQL';" | grep "no rows selected" || return

}

function 60_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_BACKUP_RESTORE {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_BACKUP_RESTORE';" | grep "no rows selected" || return

}

function 61_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_AQADM_SYSCALLS {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_AQADM_SYSCALLS';" | grep "no rows selected" || return

}

function 62_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_REPCAT_SQL_UTL {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_REPCAT_SQL_UTL';" | grep "no rows selected" || return

}

function 63_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_INITJVMAUX {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='INITJVMAUX';" | grep "no rows selected" || return

}

function 64_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_STREAMS_ADM_UTL {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_STREAMS_ADM_UTL';" | grep "no rows selected" || return

}

function 65_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_AQADM_SYS {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_AQADM_SYS';" | grep "no rows selected" || return

}

function 66_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_STREAMS_RPC {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_STREAMS_RPC';" | grep "no rows selected" || return

}

function 67_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_PRVTAQIM {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_PRVTAQIM';" | grep "no rows selected" || return

}

function 68_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_LTADM {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='LTADM';" | grep "no rows selected" || return

}

function 69_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_WWV_DBMS_SQL {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='WWV_DBMS_SQL';" | grep "no rows selected" || return

}

function 70_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_WWV_EXECUTE_IMMEDIATE {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='WWV_EXECUTE_IMMEDIATE';" | grep "no rows selected" || return

}

function 71_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_IJOB {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_IJOB';" | grep "no rows selected" || return

}

function 72_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_FILE_TRANSFER {

sql_q "SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC' AND PRIVILEGE='EXECUTE' AND TABLE_NAME='DBMS_FILE_TRANSFER';" | grep "no rows selected" || return

}

function 73_Ensure_SELECT_ANY_DICTIONARY_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='SELECT ANY DICTIONARY' AND GRANTEE NOT IN ('DBA','DBSNMP','OEM_MONITOR', 'OLAPSYS','ORACLE_OCM','SYSMAN','WMSYS');" | grep "no rows selected" || return

}

function 74_Ensure_SELECT_ANY_TABLE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='SELECT ANY TABLE' AND GRANTEE NOT IN ('DBA', 'MDSYS', 'SYS', 'IMP_FULL_DATABASE', 'EXP_FULL_DATABASE', 'DATAPUMP_IMP_FULL_DATABASE', 'WMSYS', 'SYSTEM','OLAP_DBA','OLAPSYS');" | grep "no rows selected" || return

}

function 75_Ensure_AUDIT_SYSTEM_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='AUDIT SYSTEM' AND GRANTEE NOT IN ('DBA','DATAPUMP_IMP_FULL_DATABASE','IMP_FULL_DATABASE','SYS');" | grep "no rows selected" || return

}

function 76_Ensure_EXEMPT_ACCESS_POLICY_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='EXEMPT ACCESS POLICY';" | grep "no rows selected" || return

}

function 77_Ensure_BECOME_USER_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='BECOME USER' AND GRANTEE NOT IN ('DBA','SYS','IMP_FULL_DATABASE');" | grep "no rows selected" || return

}

function 78_Ensure_CREATE_PROCEDURE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='CREATE PROCEDURE' AND GRANTEE NOT IN ( 'DBA','DBSNMP','MDSYS','OLAPSYS','OWB\$CLIENT', 'OWBSYS','RECOVERY_CATALOG_OWNER','SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR','SYS','APEX_030200','APEX_040000', 'APEX_040100','APEX_040200','RESOURCE');" | grep "no rows selected" || return

}

function 79_Ensure_ALTER_SYSTEM_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='ALTER SYSTEM' AND GRANTEE NOT IN ('SYS','SYSTEM','APEX_030200','APEX_040000', 'APEX_040100','APEX_040200','DBA');" | grep "no rows selected" || return

}

function 80_Ensure_CREATE_ANY_LIBRARY_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='CREATE ANY LIBRARY' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA','IMP_FULL_DATABASE');" | grep "no rows selected" || return

}

function 81_Ensure_CREATE_LIBRARY_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='CREATE LIBRARY' AND GRANTEE NOT IN ('SYS','SYSTEM','DBA','SPATIAL_CSW_ADMIN_USR','XDB','EXFSYS','MDSYS','SPATIAL_WFS_ADMI N_USR');" | grep "no rows selected" || return

}

function 82_Ensure_GRANT_ANY_OBJECT_PRIVILEGE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='GRANT ANY OBJECT PRIVILEGE' AND GRANTEE NOT IN ('DBA','SYS','IMP_FULL_DATABASE','DATAPUMP_IMP_FULL_DATABASE');" | grep "no rows selected" || return

}

function 83_Ensure_GRANT_ANY_ROLE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='GRANT ANY ROLE' AND GRANTEE NOT IN ('DBA','SYS','DATAPUMP_IMP_FULL_DATABASE','IMP_FULL_DATABASE', 'SPATIAL_WFS_ADMIN_USR','SPATIAL_CSW_ADMIN_USR');" | grep "no rows selected" || return

}

function 84_Ensure_GRANT_ANY_PRIVILEGE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='GRANT ANY PRIVILEGE' AND GRANTEE NOT IN ('DBA','SYS','IMP_FULL_DATABASE','DATAPUMP_IMP_FULL_DATABASE');" | grep "no rows selected" || return

}

function 85_Ensure_DELETE_CATALOG_ROLE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE granted_role='DELETE_CATALOG_ROLE' AND GRANTEE NOT IN ('DBA','SYS');" | grep "no rows selected" || return

}

function 86_Ensure_SELECT_CATALOG_ROLE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE granted_role='SELECT_CATALOG_ROLE' AND grantee not in ('DBA','SYS','IMP_FULL_DATABASE','EXP_FULL_DATABASE','OEM_MONITOR','SYSMAN');" | grep "no rows selected" || return

}

function 87_Ensure_EXECUTE_CATALOG_ROLE_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE granted_role='EXECUTE_CATALOG_ROLE' AND grantee not in ('DBA','SYS','IMP_FULL_DATABASE','EXP_FULL_DATABASE');" | grep "no rows selected" || return

}

function 88_Ensure_DBA_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA' AND GRANTEE NOT IN ('SYS','SYSTEM');" | grep "no rows selected" || return

}

function 89_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_AUD {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_TAB_PRIVS WHERE TABLE_NAME='AUD\$' AND GRANTEE NOT IN ('DELETE_CATALOG_ROLE');" | grep "no rows selected" || return

}

function 90_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_USER_HISTORY {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_TAB_PRIVS WHERE TABLE_NAME='USER_HISTORY\$';" | grep "no rows selected" || return

}

function 91_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_LINK {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_TAB_PRIVS WHERE TABLE_NAME='LINK\$';" | grep "no rows selected" || return

}

function 92_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_SYSUSER {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_TAB_PRIVS WHERE TABLE_NAME='USER\$' AND GRANTEE NOT IN ('CTXSYS','XDB','APEX_030200', 'APEX_040000','APEX_040100','APEX_040200','ORACLE_OCM');" | grep "no rows selected" || return

}

function 93_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_DBA {

sql_q "SELECT * FROM DBA_TAB_PRIVS WHERE TABLE_NAME LIKE 'DBA_%' AND GRANTEE NOT IN ('APPQOSSYS','AQ_ADMINISTRATOR_ROLE','CTXSYS', 'EXFSYS','MDSYS','OLAP_XS_ADMIN','OLAPSYS','ORDSYS','OWB\$CLIENT','OWBSYS', 'SELECT_CATALOG_ROLE','WM_ADMIN_ROLE','WMSYS','XDBADMIN','LBACSYS', 'ADM_PARALLEL_EXECUTE_TASK','CISSCANROLE') AND NOT REGEXP_LIKE(grantee,'^APEX_0[3-9][0-9][0-9][0-9][0-9]\$');" | grep "no rows selected" || return

}

function 94_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_SYSSCHEDULER_CREDENTIAL {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_TAB_PRIVS WHERE TABLE_NAME='SCHEDULER\$_CREDENTIAL';" | grep "no rows selected" || return

}

function 95_Ensure_SYSUSERMIG_Has_Been_Dropped {

sql_q "SELECT OWNER, TABLE_NAME FROM ALL_TABLES WHERE OWNER='SYS' AND TABLE_NAME='USER\$MIG';" | grep "no rows selected" || return

}

function 96_Ensure_ANY_Is_Revoked_from_Unauthorized_GRANTEE {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE LIKE '%ANY%' AND GRANTEE NOT IN ('AQ_ADMINISTRATOR_ROLE','DBA','DBSNMP','EXFSYS', 'EXP_FULL_DATABASE','IMP_FULL_DATABASE','DATAPUMP_IMP_FULL_DATABASE', 'JAVADEBUGPRIV','MDSYS','OEM_MONITOR','OLAPSYS','OLAP_DBA','ORACLE_OCM', 'OWB\$CLIENT','OWBSYS','SCHEDULER_ADMIN','SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR','SYS','SYSMAN','SYSTEM','WMSYS','APEX_030200', 'APEX_040000','APEX_040100','APEX_040200','LBACSYS','OUTLN');" | grep "no rows selected" || return

}

function 97_Ensure_DBA_SYS_PRIVS_Is_Revoked_from_Unauthorized_GRANTEE_with_ADMIN_OPTION_Set_to_YES {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE ADMIN_OPTION='YES' AND GRANTEE not in ('AQ_ADMINISTRATOR_ROLE','DBA','OWBSYS', 'SCHEDULER_ADMIN','SYS','SYSTEM','WMSYS', 'APEX_030200','APEX_040000','APEX_040100','APEX_040200');"

}

function 98_Ensure_Proxy_Users_Have_Only_CONNECT_Privilege {

sql_q "SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE IN ( SELECT PROXY FROM DBA_PROXIES ) AND GRANTED_ROLE NOT IN ('CONNECT');" | grep "no rows selected" || return

}

function 99_Ensure_EXECUTE_ANY_PROCEDURE_Is_Revoked_from_OUTLN {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ANY PROCEDURE' AND GRANTEE='OUTLN';" | grep "no rows selected" || return

}

function 100_Ensure_EXECUTE_ANY_PROCEDURE_Is_Revoked_from_DBSNMP {

sql_q "SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ANY PROCEDURE' AND GRANTEE='DBSNMP';" | grep "no rows selected" || return

}

function 101_Enable_USER_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='USER' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 102_Enable_ALTER_USER_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='ALTER USER' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 103_Enable_DROP_USER_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='DROP USER' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 104_Enable_ROLE_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='ROLE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 105_Enable_SYSTEM_GRANT_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='SYSTEM GRANT' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 106_Enable_PROFILE_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='PROFILE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 107_Enable_ALTER_PROFILE_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='ALTER PROFILE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 108_Enable_DROP_PROFILE_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='DROP PROFILE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 109_Enable_DATABASE_LINK_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='DATABASE LINK' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 110_Enable_PUBLIC_DATABASE_LINK_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='PUBLIC DATABASE LINK' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 111_Enable_PUBLIC_SYNONYM_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='PUBLIC SYNONYM' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 112_Enable_SYNONYM_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='SYNONYM' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 113_Enable_GRANT_DIRECTORY_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='GRANT DIRECTORY' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 114_Enable_SELECT_ANY_DICTIONARY_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='SELECT ANY DICTIONARY' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 115_Enable_GRANT_ANY_OBJECT_PRIVILEGE_Audit_Option {

sql_q "SELECT PRIVILEGE, SUCCESS, FAILURE FROM DBA_PRIV_AUDIT_OPTS WHERE PRIVILEGE='GRANT ANY OBJECT PRIVILEGE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 116_Enable_GRANT_ANY_PRIVILEGE_Audit_Option {

sql_q "SELECT PRIVILEGE, SUCCESS, FAILURE FROM DBA_PRIV_AUDIT_OPTS WHERE PRIVILEGE='GRANT ANY PRIVILEGE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 117_Enable_DROP_ANY_PROCEDURE_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='DROP ANY PROCEDURE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 118_Enable_ALL_Audit_Option_on_SYSAUD {

sql_q "SELECT * FROM DBA_OBJ_AUDIT_OPTS WHERE OBJECT_NAME='AUD\$' AND ALT='A/A' AND AUD='A/A' AND COM='A/A' AND DEL='A/A' AND GRA='A/A' AND IND='A/A' AND INS='A/A' AND LOC='A/A' AND REN='A/A' AND SEL='A/A' AND UPD='A/A' AND FBK='A/A';" | grep "no rows selected" || return

}

function 119_Enable_PROCEDURE_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='PROCEDURE' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 120_Enable_ALTER_SYSTEM_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='ALTER SYSTEM' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 121_Enable_TRIGGER_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='TRIGGER' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function 122_Enable_CREATE_SESSION_Audit_Option {

sql_q "SELECT AUDIT_OPTION, SUCCESS, FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='CREATE SESSION' AND USER_NAME IS NULL AND PROXY_NAME IS NULL AND SUCCESS = 'BY ACCESS' AND FAILURE = 'BY ACCESS';" | grep "no rows selected" || return

}

function oracle11 {

	header

	main_manual 1_Ensure_the_Appropriate_VersionPatches_for_Oracle_Software_Is_Installed
	main_manual 2_Ensure_All_Default_Passwords_Are_Changed
	main_manual 3_Ensure_All_Sample_Data_And_Users_Have_Been_Removed
	main_manual 4_Ensure_SECURE_CONTROL_ltlistener_namegt_Is_Set_In_listenerora
	main_auto 5_Ensure_extproc_Is_Not_Present_in_listenerora
	main_auto 6_Ensure_ADMIN_RESTRICTIONS_ltlistener_namegt_Is_Set_to_ON
	main_auto 7_Ensure_SECURE_REGISTER_ltlistener_namegt_Is_Set_to_TCPS_or_IPC
	main_auto 8_Ensure_AUDIT_SYS_OPERATIONS_Is_Set_to_TRUE
	main_auto 9_Ensure_AUDIT_TRAIL_Is_Set_to_OS_DBEXTENDED_or_XMLEXTENDED
	main_auto 10_Ensure_GLOBAL_NAMES_Is_Set_to_TRUE
	main_auto 11_Ensure_LOCAL_LISTENER_Is_Set_Appropriately
	main_auto 12_Ensure_O7_DICTIONARY_ACCESSIBILITY_Is_Set_to_FALSE
	main_auto 13_Ensure_OS_ROLES_Is_Set_to_FALSE
	main_manual 14_Ensure_REMOTE_LISTENER_Is_Empty
	main_auto 15_Ensure_REMOTE_LOGIN_PASSWORDFILE_Is_Set_to_NONE
	main_auto 16_Ensure_REMOTE_OS_AUTHENT_Is_Set_to_FALSE
	main_auto 17_Ensure_REMOTE_OS_ROLES_Is_Set_to_FALSE
	main_manual 18_Ensure_UTIL_FILE_DIR_Is_Empty
	main_auto 19_Ensure_SEC_CASE_SENSITIVE_LOGON_Is_Set_to_TRUE
	main_auto 20_Ensure_SEC_MAX_FAILED_LOGIN_ATTEMPTS_Is_Set_to_10
	main_auto 21_Ensure_SEC_PROTOCOL_ERROR_FURTHER_ACTION_Is_Set_to_DELAY3_or_DROP3
	main_auto 22_Ensure_SEC_PROTOCOL_ERROR_TRACE_ACTION_Is_Set_to_LOG
	main_auto 23_Ensure_SEC_RETURN_SERVER_RELEASE_BANNER_Is_Set_to_FALSE
	main_auto 24_Ensure_SQL92_SECURITY_Is_Set_to_TRUE
	main_auto 25_Ensure_TRACE_FILES_PUBLIC_Is_Set_to_FALSE
	main_auto 26_Ensure_RESOURCE_LIMIT_Is_Set_to_TRUE
	main_auto 27_Ensure_FAILED_LOGIN_ATTEMPTS_Is_Less_than_or_Equal_to_5
	main_auto 28_Ensure_PASSWORD_LOCK_TIME_Is_Greater_than_or_Equal_to_1
	main_auto 29_Ensure_PASSWORD_LIFE_TIME_Is_Less_than_or_Equal_to_90
	main_auto 30_Ensure_PASSWORD_REUSE_MAX_Is_Greater_than_or_Equal_to_20
	main_auto 31_Ensure_PASSWORD_REUSE_TIME_Is_Greater_than_or_Equal_to_365
	main_auto 32_Ensure_PASSWORD_GRACE_TIME_Is_Less_than_or_Equal_to_5
	main_auto 33_Ensure_DBA_USERSPASSWORD_Is_Not_Set_to_EXTERNAL_for_Any_User
	main_auto 34_Ensure_PASSWORD_VERIFY_FUNCTION_Is_Set_for_All_Profiles
	main_auto 35_Ensure_SESSIONS_PER_USER_Is_Less_than_or_Equal_to_10
	main_auto 36_Ensure_No_Users_Are_Assigned_the_DEFAULT_Profile
	main_auto 37_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_ADVISOR
	main_auto 38_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_CRYPTO
	main_auto 39_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_JAVA
	main_auto 40_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_JAVA_TEST
	main_auto 41_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_JOB
	main_auto 42_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_LDAP
	main_auto 43_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_LOB
	main_auto 44_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_OBFUSCATION_TOOLKIT
	main_auto 45_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_RANDOM
	main_auto 46_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_SCHEDULER
	main_auto 47_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_SQL
	main_auto 48_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_XMLGEN
	main_auto 49_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_XMLQUERY
	main_auto 50_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_FILE
	main_auto 51_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_INADDR
	main_auto 52_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_TCP
	main_auto 53_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_MAIL
	main_auto 54_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_SMTP
	main_auto 55_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_DBWS
	main_auto 56_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_ORAMTS
	main_auto 57_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_UTL_HTTP
	main_auto 58_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_HTTPURITYPE
	main_auto 59_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_SYS_SQL
	main_auto 60_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_BACKUP_RESTORE
	main_auto 61_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_AQADM_SYSCALLS
	main_auto 62_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_REPCAT_SQL_UTL
	main_auto 63_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_INITJVMAUX
	main_auto 64_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_STREAMS_ADM_UTL
	main_auto 65_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_AQADM_SYS
	main_auto 66_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_STREAMS_RPC
	main_auto 67_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_PRVTAQIM
	main_auto 68_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_LTADM
	main_auto 69_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_WWV_DBMS_SQL
	main_auto 70_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_WWV_EXECUTE_IMMEDIATE
	main_auto 71_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_IJOB
	main_auto 72_Ensure_EXECUTE_Is_Revoked_from_PUBLIC_on_DBMS_FILE_TRANSFER
	main_auto 73_Ensure_SELECT_ANY_DICTIONARY_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 74_Ensure_SELECT_ANY_TABLE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 75_Ensure_AUDIT_SYSTEM_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 76_Ensure_EXEMPT_ACCESS_POLICY_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 77_Ensure_BECOME_USER_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 78_Ensure_CREATE_PROCEDURE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 79_Ensure_ALTER_SYSTEM_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 80_Ensure_CREATE_ANY_LIBRARY_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 81_Ensure_CREATE_LIBRARY_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 82_Ensure_GRANT_ANY_OBJECT_PRIVILEGE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 83_Ensure_GRANT_ANY_ROLE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 84_Ensure_GRANT_ANY_PRIVILEGE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 85_Ensure_DELETE_CATALOG_ROLE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 86_Ensure_SELECT_CATALOG_ROLE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 87_Ensure_EXECUTE_CATALOG_ROLE_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 88_Ensure_DBA_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 89_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_AUD
	main_auto 90_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_USER_HISTORY
	main_auto 91_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_LINK
	main_auto 92_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_SYSUSER
	main_auto 93_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_DBA
	main_auto 94_Ensure_ALL_Is_Revoked_from_Unauthorized_GRANTEE_on_SYSSCHEDULER_CREDENTIAL
	main_auto 95_Ensure_SYSUSERMIG_Has_Been_Dropped
	main_auto 96_Ensure_ANY_Is_Revoked_from_Unauthorized_GRANTEE
	main_auto 97_Ensure_DBA_SYS_PRIVS_Is_Revoked_from_Unauthorized_GRANTEE_with_ADMIN_OPTION_Set_to_YES
	main_auto 98_Ensure_Proxy_Users_Have_Only_CONNECT_Privilege
	main_auto 99_Ensure_EXECUTE_ANY_PROCEDURE_Is_Revoked_from_OUTLN
	main_auto 100_Ensure_EXECUTE_ANY_PROCEDURE_Is_Revoked_from_DBSNMP
	main_auto 101_Enable_USER_Audit_Option
	main_auto 102_Enable_ALTER_USER_Audit_Option
	main_auto 103_Enable_DROP_USER_Audit_Option
	main_auto 104_Enable_ROLE_Audit_Option
	main_auto 105_Enable_SYSTEM_GRANT_Audit_Option
	main_auto 106_Enable_PROFILE_Audit_Option
	main_auto 107_Enable_ALTER_PROFILE_Audit_Option
	main_auto 108_Enable_DROP_PROFILE_Audit_Option
	main_auto 109_Enable_DATABASE_LINK_Audit_Option
	main_auto 110_Enable_PUBLIC_DATABASE_LINK_Audit_Option
	main_auto 111_Enable_PUBLIC_SYNONYM_Audit_Option
	main_auto 112_Enable_SYNONYM_Audit_Option
	main_auto 113_Enable_GRANT_DIRECTORY_Audit_Option
	main_auto 114_Enable_SELECT_ANY_DICTIONARY_Audit_Option
	main_auto 115_Enable_GRANT_ANY_OBJECT_PRIVILEGE_Audit_Option
	main_auto 116_Enable_GRANT_ANY_PRIVILEGE_Audit_Option
	main_auto 117_Enable_DROP_ANY_PROCEDURE_Audit_Option
	main_auto 118_Enable_ALL_Audit_Option_on_SYSAUD
	main_auto 119_Enable_PROCEDURE_Audit_Option
	main_auto 120_Enable_ALTER_SYSTEM_Audit_Option
	main_auto 121_Enable_TRIGGER_Audit_Option
	main_auto 122_Enable_CREATE_SESSION_Audit_Option

}



filename=Oracle-checklists-$( date +"%m-%d-%y-%H-%M" )-$(hostname)

oracle11 &> $filename.txt
oracle11

echo
echo
echo "*Report : $filename.txt"
echo
