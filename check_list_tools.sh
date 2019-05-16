#!/usr/bin/env bash

#set -x
#------------------parameter definitions---------------------------#
TMPFIFO=/tmp/$$.fifo
CURRENTPATH=$(cd "$(dirname "$0")"; pwd)
SYSTEMCHECKSCRIPT=$CURRENTPATH/system_check.sh
HARDWARETEMPLATE=$CURRENTPATH/hardware_template
K8STEMPLATE=$CURRENTPATH/K8S_template
SYSTEMCHECKSCRIPTGPG=$CURRENTPATH/system_check.sh.gpg
HARDWARETEMPLATEGPG=$CURRENTPATH/hardware_template.gpg
K8STEMPLATEGPG=$CURRENTPATH/K8S_template.gpg
FILEDATE=`date "+%Y%m%d%H%M%S"`
CHECKLOGFILE=/tmp/checklist_$FILEDATE.log
hostname=`hostname -f`
hardware_info=/tmp/hardware_info_${hostname}_$FILEDATE.info
k8s_info=/tmp/k8s_info_${hostname}_$FILEDATE.info
declare -A allnodes
declare -A alldbservers
declare -A usernamemachines
hardwaretemp_line=("6" "13" "13" "19" "10" "14")
k8stemp_line=("15" "15" "12" "15" "20" "23" "23" "22" "14" "19" "18" "21" "20" "20" "20" "20")


#------------------Trap mechanism to clean temporary files---------------------------#
trap temporyary_cleanup 1 2 3 6

temporyary_cleanup(){
  printf "Caught Signal ... all temporary files will be cleaned up.\n"
  rm -rf $CHECKLOGFILE $hardware_info $k8s_info $logfile $SYSTEMCHECKSCRIPT $HARDWARETEMPLATE $K8STEMPLATE
  printf "Done cleanup ... quitting.\n"
  exit 1
}

monitor(){
    export pstatus=true
    process=">"
    begineer=''
    while [[ $pstatus ]]; do
        sleep 3
        echo -en "$begineer" `echo $process`
        process=$process">>"
        begineer=$begineer"\b\b"
        read pstatus <&1000
        #echo -e "results1: $pstatus"
    done
}

includescripts(){
    source $SYSTEMCHECKSCRIPT > /dev/null
    echo >&1000
    echo >&1000
}

timeoutfun(){
    i=0
    while [[ $i -lt 100 ]]; do
        sleep 3
        echo "true" >&1000
        let i++
    done
}

fifoprepare(){
    fifo_name=$TMPFIFO
    mkfifo $fifo_name
    exec 1000<>$fifo_name
    rm -rf $fifo_name
}

load_system_scripts_monitor(){
    fifoprepare
    timeoutfun&
    monitor&
    includescripts
    printf "the external system_check script has been implmented successfully!!\n"
}

#----------------------Collect SMA info---------------------------#
collect_sma_info(){
    checkHA
    getSuiteVersion
    getSuiteMode
    getSuiteDbType
    getLdap
    getSmtp
    getSuiteProfile
    getNodes
    getTopNodes
    getPods
    checknfsserver
}

#----------------------Collect SMA info functions---------------------------#
checkHA() {
    hacheck=`kubectl get nodes -l master|grep -v NAME|wc -l`
    if [[ $hacheck -eq 3 ]]; then
      ha="Yes"
    else
      ha="No"
    fi
}

#------------------Get suite version---------------------------#
getSuiteVersion(){
    namespace=`kubectl get namespaces | grep itsma | awk '{print $1}'`
    versions=`kubectl get cm itsma-common-configmap -n $name_space -o yaml | grep itom_suite_version | grep -E "[0-9]{4}\.[0-9]{2}" -o`
    suiteVersion=${versions:0:7}
}

#------------------Get suite mode---------------------------#
getSuiteMode(){
    suiteMode=`kubectl get cm -n $name_space itsma-common-configmap -o yaml | grep itom_suite_mode | awk -F": " '{print $2}' |head -1`
}

#------------------Get suite db type---------------------------#
getSuiteDbType(){
    suiteDbType=`kubectl get cm -n $name_space database-configmap -o yaml | grep xservices_db_type | awk -F": " '{print $2}' |head -1`
}

#------------------Get ldap config---------------------------#
getLdap(){
    saml2=`kubectl get cm -n $name_space ldap-configmap -o yaml | grep saml2_enable | awk -F": " '{print $2}' |head -1`
    ldapServer=`kubectl get cm -n $name_space ldap-configmap -o yaml | grep ldap_server_ip | awk -F": " '{print $2}' |head -1`
    if [[ $ldapServer != "openldap-svc" ]]; then
      ldapConfigured="External"
    else
      ldapConfigured="Internal"
    fi
}

#------------------Get smtp config---------------------------#
getSmtp(){
    smtpserver=`kubectl get cm -n $name_space smtp-configmap -o yaml | grep email_smtp_server_name | awk -F": " '{print $2}' |head -1`
    chrlen=${#smtpserver}
    if [[ $chrlen -eq 0 ]]; then
      smtpConfigured="No"
    else
      smtpConfigured="Yes"
    fi
}

#------------------Get suite profile---------------------------#
getSuiteProfile(){
    suiteProfile=`kubectl get cm -n $name_space itsma-common-configmap -o yaml | grep itom_suite_size | awk -F": " '{print $2}' |head -1`
}

#------------------Get nodes---------------------------#
getNodes() {
    nodes=`kubectl get nodes`
}

#------------------Get top nodes---------------------------#
getTopNodes() {
    topNodes=`kubectl top nodes | sed 's/%/%%/g'`
}

#------------------Get pods---------------------------#
getPods() {
    pods=`kubectl get pods --all-namespaces -o wide --show-all`
}

#------------------check file existence---------------------------#

checkfile(){
    while [ "$1" != "" ]; do
        if [[ -f $1 ]]; then
            printf "we can find required file $1! in the path $CURRENTPATH\n"
            log_check "debug" "we can find required file $1 in the path $CURRENTPATH"
        else
            printf "we cannot find the required file $1 in the path $CURRENTPATH, please check it!\n"
            log_check "error" "we cannot find the required file $1 in the path $CURRENTPATH, please check it!\n"
        fi
        shift 1
    done
}

checktemplate(){ 
    template_arr=(`echo $2`)
    #echo -e ${template_arr[@]}
    #echo -e "arr is ${template_arr[0]}"
    total_lines=$3
    total_file_lines=`cat $1|wc -l`
    if [[ "$total_lines" != "$total_file_lines" ]]; then
        #printf "there are `echo $(($total_lines-$total_file_lines))` lines missing in $1 \n"
        log_check "error" "there are `echo $(($total_lines-$total_file_lines))` lines missing in $1 \n"
    else
        lines=0
        #printf "Lines: $total_lines\n"
        while IFS='' read -r line || [[ -n "$line" ]]; do
            words=`echo $line|wc -c`
            if [[ "$words" != "${template_arr[$lines]}" ]]; then
              #printf "the content of line `echo $(($lines+1))` in $1 is not matche with original template\n"  
              log_check "error" "the content of line `echo $(($lines+1))` in $1 is not matche with original template\n"
            fi
            let lines++
        done < "$1"
    fi
}
#----------------------------------------------check list logs-----------------------------------------------------------
log_check(){
    level=$1
    msg=$2
    cmd_line=$3
    case $level in
        debug)
            printf "[DEBUG]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  \n" >> $CHECKLOGFILE
            printf "${cmd_line}\n" >> $CHECKLOGFILE;;
        info)
            printf "$msg\n"
            printf "[INFO]    `date "+%Y-%m-%d %H:%M:%S"` : $msg  \\n" >> $CHECKLOGFILE ;;
        error)
            printf "$msg\n"
            printf "[ERROR]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  \n" >> $CHECKLOGFILE ;;
        warn)
            printf "$msg\n"
            printf "[WARN]    `date "+%Y-%m-%d %H:%M:%S"` : $msg  \n" >> $CHECKLOGFILE ;;
        cmd)
            $cmd_line;;
        begin)
            printf "$msg  \n" >> $CHECKLOGFILE ;;
        end)
            printf "$msg  \n" >> $CHECKLOGFILE ;;
        fatal)
            printf "$msg\n"
            printf "[FATAL]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  \n" >> $CHECKLOGFILE
            printf "[INFO]    `date "+%Y-%m-%d %H:%M:%S"` : Please refer to the Troubleshooting section in suite help center for help on how to resolve this error.  \n" >> $CHECKLOGFILE
            exit 1
            ;;
        summary)
            printf "[WARN]    : $msg \n"  >> ${CHECKLOGFILE}_tmp ;;
        *)
            printf "$msg \n"
            printf "[INFO] `date "+%Y-%m-%d %H:%M:%S"` : $msg  \n" >> $CHECKLOGFILE ;;
    esac
}

#--------------------Check any errors in the log files---------------------------#
error_check_logfile(){
    error_exist_logfile=$(cat $1|grep ERROR)
    if [[ ! -n $error_exist_logfile ]]; then
        printf "all pre-requistions tasks have all passed\n"
    else
        printf "there are some errors, please correct it before running this scripts\n"
        printf "Errors:\n"
        printf "$error_exist_logfile\n"
        rm -rf $SYSTEMCHECKSCRIPT $HARDWARETEMPLATE $K8STEMPLATE
        exit 1
    fi
}

#------------------------List all nodes and DB&NFS-----------------------#
checknfsserver(){
    if [ $is_nfs_server == true ]; then
        allnodes+=(["NFS_server"]=$local_hostname)
    else
        pvlist=`kubectl get pv -n $name_space|grep -v NAME|cut -d " " -f1`
        #printf "$pvlist\n"
        while IFS='' read -r line || [[ -n "$line" ]]; do
            nfs_volume_server=`kubectl describe pv ${line} -n $name_space|grep "Server:" | awk 'begin{FS=":"}{print $2}'`
            break
        done <<< "$pvlist"
        if [[ -n $allnodes[$nfs_volume_server] ]]; then
            allnodes+=(["$nfs_volume_server"]="NFS_Server")    
        else
            allnodes["$nfs_volume_server"]=$allnodes["$nfs_volume_server"]"_NFS"    
        fi
        
    fi
}

checkdbserver(){
    #name_space=itsma1
    dblist=`kubectl describe cm database-configmap -n $name_space|grep db_host`
    while IFS='' read -r line || [[ -n "$line" ]]; do
        #db_server=`kubectl describe cm database-configmap -n $name_space |grep -A 2 "$line"|awk '{printf (NR%3)==0?$0"\n":$0}'`
        db_server=`kubectl describe cm database-configmap -n $name_space |grep -A 2 "$line"|awk 'NR==3'`
        alldbservers+=(["$line"]=$db_server)
    done <<< "$dblist"
    alldb=${alldbservers[@]}
    alldb=($(echo ${alldb[*]} | sed 's/ /\n/g'|sort -u))
    #echo ${alldb[*]}
    for j in ${alldb[@]}; do
        if [[ $(ping -c 1 -W 3 $j > /dev/null 2>&1 ; echo $?) == 0 ]]; then
            if [[ -n $allnodes[$j] ]]; then
                allnodes+=([$j]="DB_Server_$j")
            else
                allnodes[$j]=$allnodes["$j"]"_DataBase"
            fi
            
        fi
    done
}

#------------------------List all nodes and DB&NFS-----------------------#
listallmachines(){
    `kubectl get nodes|grep -v NAME|cut -d " " -f1>$CURRENTPATH/nodes`
    node_type=null
    mastercount=1
    workercount=1
    while IFS='' read -r line || [[ -n "$line" ]]; do
        get_node $line
        case $node_type in
             "Master") 
                allnodes+=([$line]="Master$mastercount")
                let "mastercount++"
                ;;
             "Worker") 
                allnodes+=([$line]="Worker$workercount")
                let "workercount++"
                ;;
                *) printf "Sorry I cannot understand"  
                ;;
        esac
    done < "$CURRENTPATH/nodes"
    `rm -rf $CURRENTPATH/nodes`
}

#------------------------check k8s installed in this server---------------------#
checkk8s(){
    #k8sgetns=`kubectl get cluster-info` #test the else branch
    k8sgetns=`kubectl get ns`
    if [ "$?" == "0" ]; then
        printf "k8s has been installed in this machine with path $K8S_HOME\n"
    else
        printf "k8s is not installed in this server, please run this script in the cluster node!"
        exit 1
    fi
}

printallnodes(){
    for key in ${!allnodes[@]};do
        echo -e "$key+%%%%%%%%%%%%%%%%%%+${allnodes[$key]}"
    done

}

printalllines(){
    for key in ${!hardwaretemp_line[@]};do
        echo -e "$key+%%%%%%%%%%%%%%%%%%+${hardwaretemp_line[$key]}"
    done
}

#------------------read and splite the template---------------------------#
readsplittemplate(){
    #set -x
    while IFS='' read -r line || [[ -n "$line" ]]; do
        IFS=':' read -r wholeline <<< "$line"
        IFS='.' read -r number content <<< "$wholeline"
        log_check "debug" "we are reading $content in the template $1"
        readwritecontent "$content" $number
    done < "$1"
    #set +x
}

#----------------------------read content functions--------------------------------------------#
readwritecontent(){
    #set -x
    case $1 in 
        "OS")writecontentandoutput "$1" "$2" $hardware_info $kernal "we are writing OS info: $kernal information to the $hardware_info file";;
        "CPU model")writecontentandoutput "$1" "$2" $hardware_info "$cpu_type type CPU" "we are writing CPU type info: $cpu_type CPU model information to the $hardware_info file";;
        "CPU cores")writecontentandoutput "$1" "$2" $hardware_info "$cpu_core cores CPU" "we are writing CPU cores info: $cpu_core cores to the $hardware_info file";;
        "Memory")echo "$2.$1:Memory Info:" >> $hardware_info
        echo "$mem_info" >> $hardware_info
        echo  $3 >> $hardware_info 
        log_check "debug" "we are writing Memory info to the $hardware_info file"
        log_check "debug" "$mem_info";;
        "CPU frequencies") writecontentandoutput "$1" "$2" $hardware_info "$cpu_frq GHz" "we are writing CPU Frequency info $cpu_frq GHz to the $hardware_info file";;
        "Free space") writecontentandoutput "$1" "$2" $hardware_info "$available_disk GB" "we are writing Free space info: $available_disk GB to the $hardware_info file";;
        "CDF version")writecontentandoutput "$1" "$2" $k8s_info "`cat $K8S_HOME/version.txt`" "we are writing CDF information `cat $K8S_HOME/version.txt` information to the $k8s_info file";;
        "SMA version")writecontentandoutput "$1" "$2" $k8s_info "$suiteVersion" "we are writing SMA information ${suiteVersion} to the $k8s_info file";;
        "SMA mode")writecontentandoutput "$1" "$2" $k8s_info "$suiteMode" "we are writing SMA information ${suiteMode} to the $k8s_info file";;
        "SMA profile")writecontentandoutput "$1" "$2" $k8s_info "$suiteProfile" "we are writing SMA information ${suiteProfile} to the $k8s_info file";;
        "Master HA or Not")writecontentandoutput "$1" "$2" $k8s_info "$ha" "we are writing Master HA or not information to the $k8s_info file";;
        "Kubernetes get node") echo "$2.$1s:" >> $k8s_info 
        echo "$nodes" >> $k8s_info
        echo $3 >> $k8s_info 
        log_check "debug" "we are writing k8s nodes information to the $k8s_info file"
        log_check "debug" "$nodes";;
        "Kubernetes top node") echo "$2.$1s:" >> $k8s_info 
        echo "$topNodes" >> $k8s_info
        echo $3 >> $k8s_info
        log_check "debug" "we are writing k8s top nodes information to the $k8s_info file"
        log_check "debug" "$topNodes";;
        "Kubernetes get pod") echo "$2.$1s:" >> $k8s_info 
        echo "$pods" >> $k8s_info
        echo $3 >> $k8s_info 
        log_check "debug" "we are writing k8s pods information to the $k8s_info file"
        log_check "debug" "$pods";;
        "NFS Server")writecontentandoutput "$1" "$2" $k8s_info "$allnodes[$nfs_volume_server]" "we are writing NFS Server: $allnodes[$nfs_volume_server] information to the $k8s_info file";;
        #"NFS Disk Space")writecontentandoutput "$1" "$2" $k8s_info $kernal "we are writing OS info: $kernal information to the $k8s_info file";;
        "Database Type")writecontentandoutput "$1" "$2" $k8s_info "$suiteDbType" "we are writing database type $suiteDbType to the $k8s_info file";;
        #"Database Version")writecontentandoutput "$1" "$2" $k8s_info $kernal "we are writing OS info: $kernal information to the $k8s_info file";;
        "LDAP Configured")writecontentandoutput "$1" "$2" $k8s_info "$ldapConfigured" "we are writing LDAP Configured: $ldapConfigured information to the $k8s_info file";;
        "SMTP Configured")writecontentandoutput "$1" "$2" $k8s_info "$smtpConfigured" "we are writing smtp configured: $smtpConfigured to the $k8s_info file";;
        "SAML Configured")writecontentandoutput "$1" "$2" $k8s_info "$saml2" "we are writing saml configured: $saml2 to the $k8s_info file";;
        #"Upgraded or not")writecontentandoutput "$1" "$2" $k8s_info $kernal "we are writing OS info: $kernal information to the $k8s_info file";;
        *) printf "Invalid options";;
    esac
    #set +x
}

writecontentandoutput(){
    #set -x
    echo "$2.$1:$4">> $3 
    echo  $6 >> $3
    log_check "debug" "$5"
    #set +x
}
#----------------------------Colllect information from this machine----------------------------------------#
collectcpuinfo(){
    #set -x
    export cpu_frq=`cat /proc/cpuinfo | grep "model name" | cut -f2 -d "@" | uniq |awk 'BEGIN{FS="GHz"}{print $1}'`
    export cpu_type=`cat /proc/cpuinfo | grep "model name" | uniq | cut -f2 -d ":"| cut -f1 -d "@"`
    export cpu_version=`cat /proc/cpuinfo | grep name | cut -f6 -d " " | uniq |awk 'BEGIN{FS="-"}{print $1}'`
    export cpu_version_all=`cat /proc/cpuinfo | grep name | cut -f6 -d " " | uniq`
    export cpu_version_min=`cat /proc/cpuinfo | grep name | cut -f6 -d " " | uniq |awk 'BEGIN{FS="-"}{print $1}'|awk 'BEGIN{FS="E"}{print $2}'`
    #set +x
}

#------------------ssh connect to other nodes---------------------------#
sshnodesandreadinfo(){
    #set -x
    for nodename in ${!allnodes[@]};do
        case $allnodes[$nodename] in
            Master* )
                hardware_info=/tmp/${nodename}_${allnodes[$nodename]}.info
                extracommands=" "
                if [[ $allnodes[$nodename] =~ "*DataBase*" ]]; then
                    extracommands="DBcommand "
                elif [[ $allnodes[$nodename] =~ "*NFS*" ]]; then
                    extracommands=$extracommands"NFScommand"
                fi
                printf "we are collecting the machine data from node $nodename\n"
                sshmachine ${allnodes[$nodename]} "check_k8s_home" "list_os_version" "list_system_details" "$extracommands"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $nodename\n"
                ;;
            Worker* )
                extracommands=" "
                if [[ $allnodes[$nodename] =~ "*DataBase*" ]]; then
                    extracommands="DBcommand "
                elif [[ $allnodes[$nodename] =~ "*NFS*" ]]; then
                    extracommands=$extracommands"NFScommand"
                fi
                hardware_info=/tmp/${nodename}_${allnodes[$nodename]}.info
                printf "we are collecting the machine data from node $nodename\n"
                sshmachine ${allnodes[$nodename]} "check_k8s_home" "list_os_version" "list_system_details" "$extracommands"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $nodename\n"
                ;;
            NFS_server )
                hardware_info=/tmp/${nodename}_${allnodes[$nodename]}.info
                printf "we are collecting the machine data from node $nodename\n"
                sshmachine ${allnodes[$nodename]} "check_k8s_home" "list_os_version" "list_system_details" "$extracommands"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $nodename\n"
                ;;
            dbserver* )
                hardware_info=/tmp/${nodename}_${allnodes[$nodename]}.info
                printf "we are collecting the machine data from node $nodename\n"
                sshmachine ${allnodes[$nodename]} "check_k8s_home" "list_os_version" "list_system_details" "echo -e $available_disk"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $nodename\n"
                ;;
                * )
                printf "Sorry! Whoops\n"
                ;;
        esac
    done
    #set +x
}

#----------------------------SSH connect to other nodes and run commands----------------------------------------#
sshmachine(){
    printf "the admin user for machine { $1 } is ${usernamemachines[$1]}\n"
    printf "if this user is not right, please input the right in below\n"
    local username
    unsetargu="unset K8S_HOME;unset available_disk"
    read -p "Please Input the username for this machine { $1 }:" username
    commands="hostname -f;$unsetargu;source /etc/profile;\
              export logfile='/dev/null';$(typeset -f);get_local_info;collectcpuinfo" 
    for i in $(seq 2 1 $#)
    do
        commands="${commands};${!i}"
    done
    #ssh ${username}@${host} "hostname -f;$(typeset -f checkk8s);checkk8s"
    #set -x
    servername=$username||${usernamemachines[$1]}
    if [[ ! -n $username ]]; then
        servername=${usernamemachines[$1]}||$username
    elif [[ ! -n ${usernamemachines[$1]} ]]; then
        servername=$username||${usernamemachines[$1]}
    fi
    #set +x
    ssh $servername@${1} -o "StrictHostKeyChecking no" "$commands"
}

#----------------------------Check Public Cert and Generate it----------------------------------------#
crtcheck(){
    local adminname
    printf "*********we are checking public certificates existence*************\n"
    read -p "please input the right suite admin username:" adminname
    if [[ $adminname != $USER ]]; then
        su $adminname
    fi
    certpath=/$adminname/.ssh/
    files=$(ls $certpath|grep -v known_hosts)
    if [[ ! $files ]] || [[ ! $files =~ ".pub" ]]; then
        ssh-keygen
        certificates=/$adminname/.ssh/*.pub
        printf "$certificates\n"
        else
            printf "There has had a public certificate aleady\n"
    fi
    printf "*********this machine has pass the public certificates check $certificates*************\n"
}

#----------------------------Build SSH connection and pass certificates----------------------------------------#
sshestablish(){
    hosts=${allnodes[@]}
    local user
    hosts=($(echo ${hosts[*]} | sed 's/ /\n/g'|sort -u))
    local ipaddress=$(hostname -i)
    local iphost=$(hostname -f)
    for hostip in ${hosts[@]}; do   
        printf "*********ssh connection is establishing*************\n"    
        printf "*********$certificates is transmiting to the machine $hostip*************\n"    
        ssh-copy-id $hostip
        read -p "please input the user information:" user
        ssh $user@$hostip -o "StrictHostKeyChecking no" 'hostname -f'
        usernamemachines+=(["$hostip"]=$user)
        printf "*********ssh connection with $hostip has been established*************\n"
    done
    printf "*********ssh connection establish*************\n"
}

#------------------CheckList Main Function---------------------------#

decryptfiles(){
    while [ "$1" != "" ]; do
        if [[ -f $1 ]]; then
            echo iso*help | gpg --batch --yes --passphrase-fd 0 $1
        fi
        shift 1
    done
}

check_list(){
    #set -x
    printf "*********************Check List Report is Generating************************************\n"
    start=$(date +%s)
    decryptfiles $SYSTEMCHECKSCRIPTGPG $HARDWARETEMPLATEGPG $K8STEMPLATEGPG
    checkfile $SYSTEMCHECKSCRIPT $HARDWARETEMPLATE $K8STEMPLATE #check the system_check scripts/hardware templates/k8s templates
    #checktemplate $HARDWARETEMPLATE "${hardwaretemp_line[*]}" "${#hardwaretemp_line[@]}" 
    #checktemplate $K8STEMPLATE "${k8stemp_line[*]}" "${#k8stemp_line[@]}"
    error_check_logfile $CHECKLOGFILE
    #printalllines
    #crtcheck
    printf "it will load external system check scripts!!\n"
    load_system_scripts_monitor #include the system_check.sh parameters & functions
    collectcpuinfo
    collect_sma_info
    readsplittemplate "$CURRENTPATH/hardware_template"
    readsplittemplate "$CURRENTPATH/K8S_template"
    #function lookup() { printf "This is the definitions for lookup\n">/dev/null; }
    #check_k8s_home
    #listallmachines
    #checknfsserver
    #checkdbserver
    #sshestablish
    #printallnodes
    #sshnodesandreadinfo
    #sshmachine "shcitsmacorecpe03.hpeswlab.net" "checkk8s" "checkfile" "get_namespace"
    #sshmachine "16.186.79.169" "check_k8s_home" "checkfile" "get_namespace"
    rm -rf $SYSTEMCHECKSCRIPT $HARDWARETEMPLATE $K8STEMPLATE
    end=$(date +%s)
    difference=$(( end - start))
    echo "this whole scripts has been completed and takes $difference seconds!"
    printf "*********************Check List Report is Completed************************************\n"
    printf "please collect $CHECKLOGFILE $hardware_info $k8s_info ${logfile}.tar.gz and send to our IT support\n"
    #set +x
}

help_instuctions(){
    printf "*********************below is the instruction for this script*********************\n"
    printf "*********************this is the end of instruction for this script*********************\n"
}

if [[ ! "$1" ]]; then
    echo -e "no options have received!"
    echo -e "please run checklist_run -h or --help to get the instruction of this scripts"
    echo -e "please run checklist_run -r or --run to run this scripts"
fi

while [[ -n "$1" ]]; do
    case "$1" in
        "-h" ) help_instuctions;;
        "--help" ) help_instuctions;;
        "-r" ) check_list;;
        "--run" ) check_list;;
         *) echo -e "$1 is not a validate option"
            echo -e "please run checklist_run -h or --help to get the instruction of this scripts"
            echo -e "please run checklist_run -r or --run to run this scripts";;
    esac
    shift
done

#set +x
