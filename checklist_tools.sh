#!/usr/bin/env bash

#------------------parameter definitions---------------------------#
CURRENTPATH=$(cd "$(dirname "$0")"; pwd)
SYSTEMCHECKSCRIPT=$CURRENTPATH/system_check.sh
HARDWARETEMPLATE=$CURRENTPATH/hardware_template
K8STEMPLATE=$CURRENTPATH/K8S_template
FILEDATE=`date "+%Y%m%d%H%M%S"`
CHECKLOGFILE=/tmp/checklist_${FILEDATE}.log
hostname=`hostname -f`
hardware_info=/tmp/hardware_info_${hostname}.info
k8s_info=/tmp/k8s_info.info
declare -A allnodes
declare -A alldbservers
declare -A usernamemachines

#------------------check file existence---------------------------#
checkfile(){
while [ "$1" != "" ]; do
     if [[ -f $1 ]]; then
        printf "we can find required file $1!\n"
     else
     	printf "we cannot find the required file $1, please check it!\n"
     	exit 1
     fi
shift 1
done
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

#--------------------Include the whole scripts---------------------------#
includescripts(){
	source "$1" > /dev/null	
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
                allnodes+=(["Master$mastercount"]=$line)
                let "mastercount++"
                ;;
             "Worker") 
                allnodes+=(["Worker$workercount"]=$line)
                let "workercount++"
                ;;
                *) printf "Sorry I cannot understand"  
                ;;
        esac
    done < "$CURRENTPATH/nodes"
    `rm -rf $CURRENTPATH/nodes`
}
#------------------------List all nodes and DB&NFS-----------------------#
checknfsserver(){
    if [ $is_nfs_server == true ]; then
        allnodes+=(["NFS_server"]=$local_hostname)
    else
        pvlist=`kubectl get pv -n $name_space|grep -v NAME|cut -d " " -f1`
        #printf "$pvlist\n"
        while IFS='' read -r line || [[ -n "$line" ]]; do
            nfs_volume_server=`kubectl describe pv ${line} |grep "Server:" | awk 'begin{FS=":"}{print $2}'`
            break
        done <<< "$pvlist"
        allnodes+=(["NFS_server"]=$nfs_volume_server)
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
            allnodes+=(["dbserver_$j"]=$j)
        fi
    done
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

#test1(){
#    printf "AAAAAAAAAAAAAAAAAA\n"
#    printf "BBBBBBBBBBBBBBBBBB\n"
#    printf "CCCCCCCCCCCCCCCCCC\n"
#}

#------------------read and splite the template---------------------------#
readsplittemplate(){
while IFS='' read -r line || [[ -n "$line" ]]; do
    IFS=':' read -r wholeline <<< "$line"
    IFS='.' read -r number content <<< "$wholeline"
    log_check "debug" "we are reading $content in the template $1"
    readwritecontent "$content" $number
done < "$1"
}


#------------------ssh connect to other nodes---------------------------#
sshnodes(){
    for name in ${!allnodes[@]};do
        case $name in
            Master* )
                hardware_info=/tmp/hardware_info_${allnodes[$name]}.info
                printf "we are collecting the machine data from node $name\n"
                sshmachine ${allnodes[$name]} "check_k8s_home" "list_os_version" "list_system_details"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $name\n"
                ;;
            Worker* )
                hardware_info=/tmp/hardware_info_${allnodes[$name]}.info
                printf "we are collecting the machine data from node $name\n"
                sshmachine ${allnodes[$name]} "check_k8s_home" "list_os_version" "list_system_details"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $name\n"
                ;;
            NFS_server )
                hardware_info=/tmp/hardware_info_nfs_server_${allnodes[$name]}.info
                printf "we are collecting the machine data from node $name\n"
                sshmachine ${allnodes[$name]} "check_k8s_home" "list_os_version" "list_system_details"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $name\n"
                ;;
            dbserver* )
                hardware_info=/tmp/hardware_info_dbserver_${allnodes[$name]}.info
                printf "we are collecting the machine data from node $name\n"
                sshmachine ${allnodes[$name]} "check_k8s_home" "list_os_version" "list_system_details"
                readsplittemplate $HARDWARETEMPLATE
                printf "we have finished to collect the machine data from node $name\n"
                ;;
                * )
                printf "Sorry! Whoops\n"
                ;;
        esac
    done
}

#----------------------------SSH connect to other nodes----------------------------------------#

sshmachine(){
    printf "the admin user for machine { $1 } is ${usernamemachines[$1]}\n"
    printf "if this user is not right, please input the right in below\n"
    local username
    read -p "Please Input the username for this machine { $1 }:" username
    commands="hostname -f;unset K8S_HOME;source /etc/profile;export logfile='/dev/null';$(typeset -f)"
    for i in $(seq 2 1 $#)
    do
        commands="${commands};${!i}"
    done
    #ssh ${username}@${host} "hostname -f;$(typeset -f checkk8s);checkk8s"
    set -x
    servername=$username||${usernamemachines[$1]}
    if [[ ! -n $username ]]; then
        servername=${usernamemachines[$1]}||$username
    elif [[ ! -n ${usernamemachines[$1]} ]]; then
        servername=$username||${usernamemachines[$1]}
    fi
    printf "ServerNameAA+$servername\n"
    set +x
    ssh $servername@${1} -o "StrictHostKeyChecking no" "$commands"
}

#----------------------------SSH connect to other nodes----------------------------------------#
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

#----------------------------read content functions--------------------------------------------#
readwritecontent(){
    case $1 in 
        "OS") echo "$2.$1:$kernal">> $hardware_info 
        echo  $3 >> $hardware_info
        #log_check "debug" "we are writing OS info: $kernal + $release information to the $hardware_info file"
        ;;
        "CPU model") echo "$2.$1:this machine has a $cpu_type CPU" >> $hardware_info 
        echo  $3 >> $hardware_info
        #log_check "debug" "we are writing CPU type info: $cpu_type CPU model information to the $hardware_info file"
        ;;
        "CPU cores") echo "$2.$1:this is a $cpu_core cores CPU"  >> $hardware_info
        echo  $3 >> $hardware_info 
        #log_check "debug" "we are writing CPU cores info: $cpu_core cores to the $hardware_info file"
        ;;
        "Memory") echo "$2.$1:this is the Memory info:" >> $hardware_info
        echo "$mem_info" >> $hardware_info
        echo  $3 >> $hardware_info 
        #log_check "debug" "we are writing Memory info to the $hardware_info file"
        #log_check "debug" "$mem_info_freeh"
        ;;
        "CPU frequencies") echo "$2.$1:this is CPU frequencies $cpu_frq:" >> $hardware_info
        echo $3 >> $hardware_info
        #log_check "debug" "we are writing CPU Frequency info to the $hardware_info file"
        ;;
        "Free space") echo "$2.$1:there is free space $available_disk GB" >> $hardware_info 
        echo  $3 >> $hardware_info
        #log_check "debug" "we are writing Free space info: $available_disk GB to the $hardware_info file"
        ;;
        "Database Type") echo "$2.$1:this suite configured with a $suite_db_type database" >> $hardware_info 
        echo  $3 >> $hardware_info
        #log_check "debug" "we are writing Database Type info: $suite_db_type to the $hardware_info file"
        ;;
        "Database Version") echo "$2.$1:this is the Database Version" >> $hardware_info 
        echo  $3 >> $hardware_info
        #log_check "debug" "we are writing Database Version information to the $hardware_info file"
        ;;
        "SMA mode") echo "$2.$1:SMA mode: $suite_mode" >> $k8s_info 
        echo  $3 >> $k8s_info
        #log_check "debug" "we are writing SMA mode information: $suite_mode to the $k8s_info file"
        ;;
        "SMA version") echo "$2.$1:SMA version: $suite_version" >> $k8s_info 
        echo  $3 >> $k8s_info
        #log_check "debug" "we are writing SMA version information $suite_version to the $k8s_info file"
        ;;
        "SMA profile") echo "$2.$1:SMA profile: $suite_size" >> $k8s_info 
        echo  $3 >> $k8s_info
        #log_check "debug" "we are writing SMA profile information: $suite_size to the $k8s_info file"
        ;;
        "NFS") echo "$2.$1:NFS Server: $nfs_volume_server" >> $k8s_info 
        echo  $3 >> $k8s_info
        #log_check "debug" "we are writing NFS information: $nfs_volume_server to the $k8s_info file"
        ;;
        "Kubernetes get node") echo "$2.$1:this is the result of kubectl get node:" >> $k8s_info 
        echo -e "`kubectl get node`" >> $k8s_info
        echo  $3 >> $k8s_info
        #log_check "debug" "we are writing Kubernetes get node information to the $k8s_info file"
        #log_check "debug" "`kubectl get node`"
        ;;
        "Kubernetes top node") echo "$2.$1:this is the results of kubectl top node:" >> $k8s_info 
        echo -e "`kubectl top node`" >> $k8s_info
        echo  $3 >> $k8s_info
        #log_check "debug" "we are writing Kubernetes top node information to the $k8s_info file"
        #log_check "debug" "`kubectl top node`" 
        ;;
        "Kubernetes get pod") echo "$2.$1:this is the result of kubectl get pods:" >> $k8s_info 
        echo -e "`kubectl get pods --all-namespaces -o wide --show-all`" >> $k8s_info
        echo  $3 >> $k8s_info
        #log_check "debug" "we are writing Kubernetes get pod information to the $k8s_info file"
        #log_check "debug" "`kubectl get pods --all-namespaces -o wide --show-all`"
        ;;
    esac
}

pstatus=true

monitor(){
    start=$(date +%s)
    #set -x
    i=1
    process=">"
    begineer='\b\b'
    while [[ $pstatus ]]; do
        sleep 1
        echo -en "$begineer" `echo $process$i`'%'
        process=$process">"
        begineer=$begineer"\b\b"
        let i++
    done
    #set +x
    end=$(date +%s)
    difference=$(( end - start))
    echo Time taken to execute commands is $difference seconds.
}

#------------------ssh connect to other nodes---------------------------#

check_list(){
printf "*********************Check List Report is Generating************************************\n"
checkfile $SYSTEMCHECKSCRIPT $HARDWARETEMPLATE $K8STEMPLATE #check the system_check scripts/hardware templates/k8s templates
crtcheck
source $SYSTEMCHECKSCRIPT > /dev/null #include the system_check.sh parameters & functions
function lookup() { printf "This is the definitions for lookup\n">/dev/null; }
check_k8s_home
listallmachines
checknfsserver
checkdbserver
sshestablish
#readsplittemplate $K8STEMPLATE
#printallnodes
sshnodes
#sshmachine "shcitsmacorecpe03.hpeswlab.net" "checkk8s" "checkfile" "get_namespace"
#sshmachine "16.186.79.169" "check_k8s_home" "checkfile" "get_namespace"
printf "*********************Check List Report is Completed************************************\n"
}

check_list