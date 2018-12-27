#!/bin/bash
function header {

echo
echo 
echo "                         Audit Script                          "
echo "             Apache Tomcat 7 - Security Auditor                "
echo "                      Hamed Izadi (@hezd)                      "
echo
echo "###############################################################"
echo "###############################################################"
echo

}

# echo
# read -p "Enter CATALINA_HOME directory: (e: /usr/share/apache-tomcat-7) `echo $'\n> '`" CATALINA_HOME
# echo
# read -p "Enter CATALINA_BASE directory: (e: /usr/share/apache-tomcat-7) `echo $'\n> '`" CATALINA_BASE
# echo
# echo

#Tomcat installation directory
CATALINA_HOME="/home/amp/amp"
#CATALINA_BASE is usually used when there is multiple instances of Tomcat running
CATALINA_BASE="/home/amp/amp"


function line {
  echo 
  tput setaf 7; echo "######################## MANUAL CHECK #########################"
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

function 1_Remove_extraneous_files_and_directories {

  local file="$CATALINA_HOME/webapps/js-examples"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/webapps/servlet-example"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/webapps/webdav"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/webapps/balancer"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/webapps/ROOT/admin"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/webapps/examples"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/server/webapps/host-manager"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/server/webapps/manager"
  [[ ! -d "${file}" ]] || return

  local file="$CATALINA_HOME/conf/Catalina/localhost/host-manager.xml"
  [[ ! -f "${file}" ]] || return

  local file="$CATALINA_HOME/conf/Catalina/localhost/manager.xml"
  [[ ! -f "${file}" ]] || return

}

function 2_Disable_Unused_Connectors {

  echo "* Execute the following command to find configured Connectors . Ensure only those required are present and not commented out:"
  echo "$ grep “Connector” $CATALINA_HOME/conf/server.xml"
  grep "Connector" $CATALINA_HOME/conf/server.xml

}

function 3_Alter_the_Advertised_server_info_String {

  echo "* Extract the ServerInfo.properties file and examine the server.info attribute."
  cd $CATALINA_HOME/lib
  jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties
  grep "server.info" org/apache/catalina/util/ServerInfo.properties

}

function 4_Alter_the_Advertised_server_number_String {

  echo "* Extract the ServerInfo.properties file and examine the server.number attribute."
  cd $CATALINA_HOME/lib
  jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties
  grep "server.number" org/apache/catalina/util/ServerInfo.properties

}

function 5_Alter_the_Advertised_server_built_Date {

  echo "* Extract the ServerInfo.properties file and examine the server.built attribute."
  cd $CATALINA_HOME/lib
  jar xf catalina.jar org/apache/catalina/util/ServerInfo.properties
  grep "server.built" org/apache/catalina/util/ServerInfo.properties

}

function 6_Disable_X_Powered_By_HTTP_Header_and_Rename_the_Server_Value_for_all_Connectors {

  out_p="$(grep "Connector" $CATALINA_HOME/conf/server.xml | grep "xpoweredBy=\"true\"")"
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi

}

function 7_Disable_client_facing_Stack_Traces {
#
  c_e="$(grep "<error-page>" $CATALINA_HOME/conf/web.xml | wc -l)"
  c_t="$(grep "java.lang.Throwable" $CATALINA_HOME/conf/web.xml | wc -l)"
  c_l="$(grep "<location>" $CATALINA_HOME/conf/web.xml | wc -l)"

  if [ "$c_e" = "$c_t" ] && [ "$c_t" = "$c_l" ]; then return 0; else return 1; fi

  for d in $(  find $CATALINA_HOME/webapps -maxdepth 1 -type d -not -path $CATALINA_HOME/webapps )
    do
      c_e="$(grep "<error-page>" $d/WEB-INF/web.xml | wc -l)"
      c_t="$(grep "java.lang.Throwable" $d/WEB-INF/web.xml | wc -l)"
      c_l="$(grep "<location>" $d/WEB-INF/web.xml | wc -l)"

      if [ "$c_e" = "$c_t" ] && [ "$c_t" = "$c_l" ]; then return 0; else return 1; fi
    done

}

function 8_Turn_off_TRACE {

  out_p="$(grep Connector $CATALINA_HOME/conf/server.xml | grep "allowTrace=\"true\"")"
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi

  for d in $CATALINA_HOME/webapps
    do
      out_p="$(grep "<error-page>" $d/WEB-INF/web.xml | grep "allowTrace=\"true\"")"
      if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi
    done

}

function 9ـSetـaـnondeterministicـShutdownـcommandـvalue {

  out_p="$(grep "shutdown[[:space:]]*=[[:space:]]*\"SHUTDOWN\"" $CATALINA_HOME/conf/server.xml)"
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi

}

function 10_Disable_the_Shutdown_port {

  cd $CATALINA_HOME/conf/
  grep '<Server[[:space:]]\+[^>]*port[[:space:]]*=[[:space:]]*"-1"' server.xml || return
  
}

function 11_Restrict_access_to_CATALINA_HOME {

  cd $CATALINA_HOME
  [[ -z "find . -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return

}

function 12_Restrict_access_to_CATALINA_BASE {

  cd $CATALINA_BASE
  [[ -z "find . -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return

}

function 13_Restrict_access_to_Tomcat_configuration_directory {

  cd $CATALINA_HOME/conf
  [[ -z "find . -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return
  
}

function 14_Restrict_access_to_Tomcat_logs_directory {

  cd $CATALINA_HOME
  [[ -z "find logs -follow -maxdepth 0 \( -perm /o+rwx -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return
  
}

function 15_Restrict_access_to_Tomcat_temp_directory  {

  cd $CATALINA_HOME
  [[ -z "find temp -follow -maxdepth 0 \( -perm /o+rwx -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return
}

function 16_Restrict_access_to_Tomcat_binaries_directory {

  cd $CATALINA_HOME
  [[ -z "find bin -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return
  
}

function 17_Restrict_access_to_Tomcat_web_application_directory {

  cd $CATALINA_HOME
  [[ -z "find webapps -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return

}

function 18_Restrict_access_to_Tomcat_catalina_policy  {

  cd $CATALINA_HOME/conf/
  [[ -z "find catalina.policy -follow -maxdepth 0 \( -perm /o+rwx -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return

}

function 19_Restrict_access_to_Tomcat_catalina_properties {

  cd $CATALINA_HOME/conf/
  [[ -z "find catalina.properties -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return
  
}

function 20_Restrict_access_to_Tomcat_context_xml {

  cd $CATALINA_HOME/conf
  [[ -z "find context.xml -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]]  || return
  
}

function 21_Restrict_access_to_Tomcat_logging_properties {

  cd $CATALINA_HOME/conf/
  [[ -z "find logging.properties -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return

}

function 22_Restrict_access_to_Tomcat_server_xml {

  cd $CATALINA_HOME/conf/
  [[ -z "find server.xml -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return
  
}

function 23_Restrict_access_to_Tomcat_tomcat_users_xml {

  cd $CATALINA_HOME/conf/
  [[ -z "find tomcat-users.xml -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return

}

function 24_Restrict_access_to_Tomcat_web_xml {

  cd $CATALINA_HOME/conf/
  [[ -z "find web.xml -follow -maxdepth 0 \( -perm /o+rwx,g=w -o ! -user tomcat_admin -o ! -group tomcat \) -ls" ]] || return

}

function 25_Use_secure_Realms {


  function Realm {
  grep "Realm className" $CATALINA_HOME/conf/server.xml | grep MemoryRealm || return
  grep "Realm className" $CATALINA_HOME/conf/server.xml | grep JDBCRealm  || return
  grep "Realm className" $CATALINA_HOME/conf/server.xml | grep UserDatabaseRealm  || return
  grep "Realm className" $CATALINA_HOME/conf/server.xml | grep JAASRealm  || return
  }

  Realm
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi
  
}

function 26_Use_LockOut_Realms {

  grep "lockOutTime=" $CATALINA_HOME/conf/server.xml || return
  
}

function 27_Setup_Client_cert_Authentication {

  grep "clientAuth=\"true\"" $CATALINA_HOME/conf/server.xml || return
  
}

function 28_Ensure_SSLEnabled_is_set_to_True_for_Sensitive_Connectors {

  echo "Review server.xml and ensure all Connectors sending or receiving sensitive information have the SSLEnabled attribute set to true."
  cat $CATALINA_HOME/conf/server.xml

}

function 29_Ensure_scheme_is_set_accurately_http {

  echo "Review server.xml to ensure the Connector’s scheme attribute is set to http for Connectors operating over HTTP. Also ensure the Connector’s scheme attribute is set to https for Connectors operating over HTTPS."
  cat $CATALINA_HOME/conf/server.xml

}

function 30_Ensure_secure_is_set_to_true_only_for_SSL_enabled_Connectors {



  c_e="$(grep "SSLEnabled=\"true\"" $CATALINA_HOME/conf/server.xml | wc -l)"
  c_t="$(grep "secure=\"true\"" $CATALINA_HOME/conf/server.xml | wc -l)"

  if [ "$c_e" == "$c_t" ]; then return 0; else return 1; fi


  
}

function 31_Ensure_SSL_Protocol_is_set_to_TLS_for_Secure_Connectors {

  c_e="$(grep "SSLEngine=\"on\"" $CATALINA_HOME/conf/server.xml | wc -l)"
  c_t="$(grep "sslProtocol=\"TLS\"" $CATALINA_HOME/conf/server.xml | wc -l)"

  if [ "$c_e" == "$c_t" ]; then return 0; else return 1; fi
  
}

function 32_Application_specific_logging {

  for d in $(  find $CATALINA_HOME/webapps -maxdepth 1 -type d -not -path $CATALINA_HOME/webapps )
    do
      ls -la "$d/WEB-INF/classes" | grep "logging.properties" || return
    done
  
}

function 33_Specify_file_handler_in_logging_properties_files {

  for d in $(  find $CATALINA_HOME/webapps -maxdepth 1 -type d  -not -path $CATALINA_HOME/webapps )
    do
    grep "handlers" "$d/WEB-INF/classes/logging.properties" || return
  done 
  
  grep "handlers" $CATALINA_BASE/conf/logging.properties || return
}

function 34_Ensure_className_is_set_correctly_in_context_xml {

  for d in $(  find $CATALINA_BASE/webapps/ -maxdepth 1 -type d  -not -path $CATALINA_HOME/webapps/)
    do
    grep org.apache.catalina.valves.AccessLogValve "$d/META-INF/context.xml" || return
  done
  
}

function 35_Ensure_directory_in_context_xml_is_a_secure_location {

  local file="$CATALINA_HOME/logs"
  local pattern="770"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

  local file="${1}"
  stat -L -c "%U %G" ${file} | grep -q 'tomcat_admin tomcat' || return
  
}

function 36_Ensure_pattern_in_context_xml_is_correct {

  for d in $(  find $CATALINA_BASE/webapps/ -maxdepth 1 -type d -not -path $CATALINA_BASE/webapps/ )
    do
    grep "pattern=" "$d/META-INF/context.xml" || return
  done 
  
}

function 37_Ensure_directory_in_logging_properties_is_a_secure_location {

  local file="$CATALINA_HOME/logs"
  local pattern="770"
  stat -L -c "%a" ${file} | grep "${pattern}" || return

  local file="${1}"
  stat -L -c "%U %G" ${file} | grep -q 'tomcat_admin tomcat' || return
  
}

function 38_Configure_log_file_size_limit {

  for d in $(  find $CATALINA_HOME/webapps -maxdepth 1 -type d  -not -path $CATALINA_HOME/webapps)
    do
      grep "java.util.logging.FileHandler.limit=10000" "$d/WEB-INF/classes/logging.properties" || return
    done 
  
}

function 39_Restrict_runtime_access_to_sensitive_packages {

  grep "package.access = sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat.,org.apache.jasper" $CATALINA_HOME/conf/catalina.properties || return
  
}

function 40_Starting_Tomcat_with_Security_Manager {

  echo "Review the startup configuration in /etc/init.d for Tomcat to ascertain if Tomcat is started with the -security option"  
  
}

function 41_Disabling_auto_deployment_of_applications {

  grep "autoDeploy=\"false\"" $CATALINA_HOME/conf/server.xml || return
  
}

function 42_Disable_deploy_on_startup_of_applications {

  grep "deployOnStartup=\"false\"" $CATALINA_HOME/conf/server.xml || return

}

function 43_Ensure_Web_content_directory_is_on_a_separate_partition_from_the_Tomcat_system_files {

  local filesystem="$CATALINA_HOME/webapps"
  grep "[[:space:]]${filesystem}[[:space:]]" "/etc/fstab" || return


  local filesystem="$CATALINA_HOME"
  grep "[[:space:]]${filesystem}[[:space:]]" "/etc/fstab" || return
  
}

function 44_Restrict_access_to_the_web_administration {

  out_p="$(grep -q -B 1 "<Valve" $CATALINA_HOME/conf/server.xml | grep "<!--")"
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi

}

function 45_Restrict_manager_application {

  echo "Review $CATALINA_BASE/conf/[enginename]/[hostname]/manager.xml to ascertain that the RemoteAddrValve option is uncommented and configured to only allow access to systems required to connect." 
  
}

function 46_Force_SSL_when_accessing_the_manager_application {

  grep "<transport-guarantee>CONFIDENTIAL" $CATALINA_HOME/webapps/manager/WEB-INF/web.xml || return

}

function 47_Rename_the_manager_application {

  function manager {

    local file="$CATALINA_HOME/conf/Catalina/localhost/manager.xml"
    [[ -f "${file}" ]] || return

    local file="$CATALINA_HOME/webapps/host-manager/manager.xml"
    [[ -f "${file}" ]] || return

    local file="$CATALINA_HOME/webapps/manager"
    [[ -d "${file}" ]] || return
  }

  manager
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi
  
}

function 48_Enable_strict_servlet_Compliance {

  grep "Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE=true" $CATALINA_HOME/bin/catalina.sh || return
    
}

function 49_Turn_off_session_facade_recycling {

  grep "Dorg.apache.catalina.connector.RECYCLE_FACADES=true" $CATALINA_HOME/bin/catalina.sh || return

}

function 50_Do_not_allow_additional_path_delimiters {

  grep "Dorg.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH=false" $CATALINA_HOME/bin/catalina.sh || return
  grep "Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=false" $CATALINA_HOME/bin/catalina.sh || return
  
}

function 51_Do_not_allow_custom_header_status_messages {

  grep "Dorg.apache.coyote.USE_CUSTOM_STATUS_MSG_IN_HEADER=false" $CATALINA_HOME/bin/catalina.sh || return
 
}

function 52_Configure_connectionTimeout {

  grep "connectionTimeout=\"60000\"" $CATALINA_HOME/conf/server.xml  || return
  
}

function 53_Configure_maxHttpHeaderSize {

  grep "maxHttpHeaderSize=\"8192\"" $CATALINA_HOME/conf/server.xml || return
  
}

function 54_Force_SSL_for_all_applications {

  grep "<transport-guarantee>CONFIDENTIAL" $CATALINA_HOME/conf/web.xml || return
  
}

function 55_Do_not_allow_symbolic_linking {

  find . -name context.xml | xargs grep "allowLinking="false"" || return
  
}

function 56_Do_not_run_applications_as_privileged {

  find . -name context.xml | xargs grep "privileged="false"" || return
  
}

function 57_Do_not_allow_cross_context_requests {

  find . -name context.xml | xargs grep "crossContext="false"" || return
  
}

function 58_Do_not_resolve_hosts_on_logging_valves {

  grep "enableLookups=\"false\"" $CATALINA_HOME/conf/server.xml || return
  
}

function 59_Enable_memory_leak_listener {

  grep -B 1 "<Listener className=\"org.apache.catalina.core.JreMemoryLeakPreventionListener\"" $CATALINA_HOME/conf/server.xml | grep "<!--" || return
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi

}

function 60_Setting_Security_Lifecycle_Listener {

  grep -B 1 "<Listener className=\"org.apache.catalina.security.SecurityListener\"" $CATALINA_HOME/conf/server.xml | grep "<!--" || return
  if [[ "$?" -eq 0 ]]; then return 1; elif [[  "$?" -eq 1 ]]; then return 0; fi
  
}







function tomcat7 {

header

main_auto 1_Remove_extraneous_files_and_directories
main_manual 2_Disable_Unused_Connectors
main_manual 3_Alter_the_Advertised_server_info_String
main_manual 4_Alter_the_Advertised_server_number_String
main_manual 5_Alter_the_Advertised_server_built_Date
main_auto 6_Disable_X_Powered_By_HTTP_Header_and_Rename_the_Server_Value_for_all_Connectors
main_auto 7_Disable_client_facing_Stack_Traces
main_auto 8_Turn_off_TRACE
main_auto 9ـSetـaـnondeterministicـShutdownـcommandـvalue
main_auto 10_Disable_the_Shutdown_port
main_auto 11_Restrict_access_to_CATALINA_HOME
main_auto 12_Restrict_access_to_CATALINA_BASE
main_auto 13_Restrict_access_to_Tomcat_configuration_directory
main_auto 14_Restrict_access_to_Tomcat_logs_directory
main_auto 15_Restrict_access_to_Tomcat_temp_directory
main_auto 16_Restrict_access_to_Tomcat_binaries_directory
main_auto 17_Restrict_access_to_Tomcat_web_application_directory
main_auto 18_Restrict_access_to_Tomcat_catalina_policy
main_auto 19_Restrict_access_to_Tomcat_catalina_properties
main_auto 20_Restrict_access_to_Tomcat_context_xml
main_auto 21_Restrict_access_to_Tomcat_logging_properties
main_auto 22_Restrict_access_to_Tomcat_server_xml
main_auto 23_Restrict_access_to_Tomcat_tomcat_users_xml
main_auto 24_Restrict_access_to_Tomcat_web_xml
main_auto 25_Use_secure_Realms
main_auto 26_Use_LockOut_Realms
main_auto 27_Setup_Client_cert_Authentication
main_manual 28_Ensure_SSLEnabled_is_set_to_True_for_Sensitive_Connectors
main_manual 29_Ensure_scheme_is_set_accurately_http
main_auto 30_Ensure_secure_is_set_to_true_only_for_SSL_enabled_Connectors
main_auto 31_Ensure_SSL_Protocol_is_set_to_TLS_for_Secure_Connectors
main_auto 32_Application_specific_logging
main_auto 33_Specify_file_handler_in_logging_properties_files
main_auto 34_Ensure_className_is_set_correctly_in_context_xml
main_auto 35_Ensure_directory_in_context_xml_is_a_secure_location
main_auto 36_Ensure_pattern_in_context_xml_is_correct
main_auto 37_Ensure_directory_in_logging_properties_is_a_secure_location
main_auto 38_Configure_log_file_size_limit
main_auto 39_Restrict_runtime_access_to_sensitive_packages
main_manual 40_Starting_Tomcat_with_Security_Manager
main_auto 41_Disabling_auto_deployment_of_applications
main_auto 42_Disable_deploy_on_startup_of_applications
main_auto 43_Ensure_Web_content_directory_is_on_a_separate_partition_from_the_Tomcat_system_files
main_auto 44_Restrict_access_to_the_web_administration
main_manual 45_Restrict_manager_application
main_auto 46_Force_SSL_when_accessing_the_manager_application
main_auto 47_Rename_the_manager_application
main_auto 48_Enable_strict_servlet_Compliance
main_auto 49_Turn_off_session_facade_recycling
main_auto 50_Do_not_allow_additional_path_delimiters
main_auto 51_Do_not_allow_custom_header_status_messages
main_auto 52_Configure_connectionTimeout
main_auto 53_Configure_maxHttpHeaderSize
main_auto 54_Force_SSL_for_all_applications
main_auto 55_Do_not_allow_symbolic_linking
main_auto 56_Do_not_run_applications_as_privileged
main_auto 57_Do_not_allow_cross_context_requests
main_auto 58_Do_not_resolve_hosts_on_logging_valves
main_auto 59_Enable_memory_leak_listener
main_auto 60_Setting_Security_Lifecycle_Listener
}



filename=tomcat-checklists-$( date +"%m-%d-%y-%H-%M" )

tomcat7 &> $filename.txt
tomcat7

echo
echo
echo "*Report : $filename.txt"
echo
