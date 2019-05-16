#!/bin/bash

#set -x

usage(){
    echo "Usage: $0 -l|--logfile <filename of precheck log> "
    echo "  Example: $0 -l system-check.log"
    exit 1;
}



file_date=`date "+%Y%m%d%H%M%S"`
logfile=/tmp/system_check_${file_date}.log
MIN_DISK=30
RED='\033[0;31m'
Yellow='\033[0;33m'
NC='\033[0m'
#---------------------------------------------------------
CURRENTPATH=$(cd "$(dirname "$0")"; pwd)
checklistfile=/tmp/check_list_${file_date}.log
hostname=`hostname -f`
hardware_info=/tmp/hardware_info_${hostname}.info
k8s_info=/tmp/k8s_info_${hostname}.info
checklist_folder=/tmp/check_list_${file_date}
mkdir -p $checklist_folder
#---------------------------------------------------------

while [ "$1" != "" ]; do
    case $1 in
      -l|--logfile)
        logfile=$2
        shift 2
        ;;
      *) usage ;;
    esac
done

if [ -d ${logfile} ]; then
  logfile=${logfile}/system_check_${file_date}.log
fi

#-----------------------------------------------------------------
if [ -d ${checklistfile} ]; then
  checklistfile=${checklistfile}/check_list_${file_date}.log
fi
#-----------------------------------------------------------------

ab_path=$(dirname "${logfile}")
log_folder=system_check_${file_date}_log
log_path=${ab_path}/${log_folder}
mkdir -p ${log_path}

log() {
    level=$1
    msg=$2
    cmd_line=$3
    case $level in
        debug)
            echo "[DEBUG]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $logfile
            echo "${cmd_line}" >> $logfile;;
        info)
            echo "$msg"
            echo "[INFO]    `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $logfile ;;
        error)
            echo "$msg"
            echo "[ERROR]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $logfile ;;
        warn)
            echo "$msg"
            echo "[WARN]    `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $logfile ;;
        cmd)
            $cmd_line;;
        begin)
            echo "$msg  " >> $logfile ;;
        end)
            echo "$msg  " >> $logfile ;;
        fatal)
            echo "$msg"
            echo "[FATAL]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $logfile
            echo "[INFO]    `date "+%Y-%m-%d %H:%M:%S"` : Please refer to the Troubleshooting section in suite help center for help on how to resolve this error.  " >> $logfile
            exit 1
            ;;
        summary)
            echo "[WARN]    : $msg "  >> ${logfile}_tmp ;;
        *)
            echo "$msg"
            echo "[INFO] `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $logfile ;;
    esac
}


#----------------------------------------------check list logs-----------------------------------------------------------
log_check(){
level=$1
    msg=$2
    cmd_line=$3
    case $level in
        debug)
            echo "[DEBUG]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $checklistfile
            echo "${cmd_line}" >> $checklistfile;;
        info)
            echo "$msg"
            echo "[INFO]    `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $checklistfile ;;
        error)
            echo "$msg"
            echo "[ERROR]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $checklistfile ;;
        warn)
            echo "$msg"
            echo "[WARN]    `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $checklistfile ;;
        cmd)
            $cmd_line;;
        begin)
            echo "$msg  " >> $checklistfile ;;
        end)
            echo "$msg  " >> $checklistfile ;;
        fatal)
            echo "$msg"
            echo "[FATAL]   `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $checklistfile
            echo "[INFO]    `date "+%Y-%m-%d %H:%M:%S"` : Please refer to the Troubleshooting section in suite help center for help on how to resolve this error.  " >> $checklistfile
            exit 1
            ;;
        summary)
            echo "[WARN]    : $msg "  >> ${checklistfile}_tmp ;;
        *)
            echo "$msg"
            echo "[INFO] `date "+%Y-%m-%d %H:%M:%S"` : $msg  " >> $checklistfile ;;
    esac
}

#---------------------------------------------------------------------------------------------------------

check_k8s_home(){
	if [[ -z $K8S_HOME ]]; then
        log "error" "K8S_HOME does not exist. Check if Kubernetes is installed successfully."
    else
    	log "debug" "Find Kubernetes installation folder here: $K8S_HOME"
	fi
}

get_local_info(){
    local_ipaddress=`hostname -I |cut -f1 -d " "`
    local_hostname=`hostname -f`
    if [[ -z $local_ipaddress ]]; then
      log "error" "Cannot find local IP address"
    else
      log "debug" "Local IP is $local_ipaddress"
    fi

    if [[ -z $local_hostname ]]; then
      log "error" "Cannot find local hostname"
    else
      log "debug" "Local hostname is $local_hostname"
    fi

}

getVaildDir() {
    local cur_dir=$1

    if [ -z $cur_dir ]
    then
        return 1
    fi

    if [ -d $cur_dir ]
    then
        echo $cur_dir
    else
        echo $(getVaildDir $(dirname $cur_dir))
    fi
}

checkthinpool(){
  if hash lvs 2>/dev/null; then
    log "debug" "Check thinpool" "`lvs -a`"
  fi

}
checkDisk() {
    if [[ ! -z $K8S_HOME ]]; then
        local k8s_basedir=$(getVaildDir $K8S_HOME)
    elif [[ $is_nfs_server == true ]]; then
        local k8s_basedir=$(getVaildDir $NFS_FOLDER)
    else
            local k8s_basedir=$(getVaildDir /)
    fi
    # local local_disk=$(df --si -m --direct $k8s_basedir|sed '1d'|awk '{printf "%.2f", $4/1000}')
    available_disk=$(timeout 2s df -m $k8s_basedir|sed '1d'|awk '{printf "%.2f", $4/1024}')
    local mount_point=$(timeout 2s df $k8s_basedir|sed '1d'|awk '{print $6}')

    log "info" "Free disk:      $available_disk GB"
    log "debug" "Check disk usage: " "`df -h | grep -v pod | grep -v tmpfs | grep -v devicemapper`"
    checkthinpool
    log "debug" "Check nodes usage: " "`kubectl top node`"
    if [ $(echo "$available_disk $MIN_DISK"|awk '{print $1<$2}') = 1 ]
    then
        log "summary" "Free disk: $available_disk GB is not enough. $MIN_DISK GB free hard disk is required."
    fi
}


get_master_ip(){
    master_ip=` ps -ef |grep flannel | grep -v grep |awk 'BEGIN{FS="https://"}{printf $2}'|awk 'BEGIN{FS=":"}{printf $1}'`
    if [[ -z master_ip ]]; then
      log "error" "Check if flannel is started."
    else
      log "debug" "Master IP is $master_ip"
    fi
}

check_is_master(){
    get_local_info
    get_master_ip
    NodeType=NULL

    if [[ ! -z $K8S_HOME ]]; then
        if [[ "$local_ipaddress" == "$master_ip" ]]; then
            log "debug" "Current system is Master"
            NodeType=Master
        elif [[ "$local_hostname" == "$master_ip" ]]; then
            log "debug" "Current system is Master"
            NodeType=Master
        else
            log "debug" "Current system is Worker"
            NodeType=Worker
        fi
    elif [[ $is_nfs_server == true ]]; then
            log "debug" "Current system is NFS"
            NodeType=NFS
    fi
}


check_service(){
    service_name=$1
    status=dead
    status=`systemctl status $service_name |grep Active|awk 'BEGIN{FS="("}{print $2}'|awk 'BEGIN{FS=")"}{print $1}'`
    log "info" "Checking $service_name ............ $status"
    if [[ $service_name == firewalld ]] && [[ $status != dead ]]; then
        log "summary" "Firewall is not disabled. Run 'systemctl stop $service_name'"
    fi
    if [[ $service_name == chronyd.service ]] && [[ $status == dead ]]; then
        log "summary" "Date time is not synchronized. Run 'systemctl start $service_name'"
    elif [[ $service_name == docker.service ]] && [[ $status != running ]]; then
        log "summary" "Service [$service_name] error [$status]. Run 'journalctl -u $service_name' for details"
    elif [[ $status != running ]] && [[ $service_name != firewalld ]] ; then
        log "summary" "Service [$service_name] error [$status]. Run 'systemctl start $service_name'"
    fi

}


checkNFSExports(){
    #check if NFS server export the folder.
    local CA_FILE=$PEER_CA_FILE
    local CERT_FILE=$PEER_CERT_FILE
    local KEY_FILE=$PEER_KEY_FILE
    local TMP_FOLDER=/tmp/cdf_nfs_readwrite_check
    showmount --all > /dev/null 2>&1
    if [[ $? == 0 ]]; then
        NFS_SERVER=`showmount --all |grep on |cut -f5 -d " " |awk 'BEGIN{FS=":"}{print $1}'`
    else
        NFS_SERVER=""
    fi
    if [[ -f /etc/exports ]]; then
        NFS_FOLDER=`cat /etc/exports |grep core |cut -f1 -d " "`
    else
        NFS_FOLDER=/var/vols/itom/core
    fi

    if [[ $(which showmount > /dev/null 2>&1; echo $?) != 0 ]]; then
        is_nfs_server=false
    else
        if [[ ! -z ${NFS_SERVER} ]] && [[ ! -z ${NFS_FOLDER} ]] && \
            [[ $(ping -c 1 -W 3 ${NFS_SERVER} > /dev/null 2>&1 ; echo $?) == 0 ]] ; then
            local res=`showmount -e ${NFS_SERVER}|grep "${NFS_FOLDER} "|wc -l`
            if [[ $res == 0 ]]; then
                is_nfs_server=false
            else
                if [[ ! -d ${TMP_FOLDER} ]]; then
                    mkdir -p ${TMP_FOLDER}
                fi
                if ! grep -qs '${TMP_FOLDER}' /proc/mounts; then
                    umount ${TMP_FOLDER} >/dev/null 2>&1
                    is_nfs_server=true
                fi
            fi
        else
            is_nfs_server=false
        fi
    fi
}

get_node(){
    node_name=$1
    label=`kubectl describe node $node_name | awk '/Roles/{flag=1;next}/Annotations/{flag=0}flag'`
    num=`kubectl describe node $node_name | awk '/Roles/{flag=1;next}/Annotations/{flag=0}flag'| grep loadbalancer  | wc -l`
    num1=`kubectl describe node $node_name | awk '/Roles/{flag=1;next}/Annotations/{flag=0}flag'| grep Worker | wc -l`
    if [[ $num -eq 1 ]]; then
      node_type="Master"
    elif [[ $num1 -eq 1 ]]; then
      node_type="Worker"
    else
      node_type="N/A"
    fi
    log "info" "$node_type:  `kubectl get node | grep -m 1 $node_name`"
    log "debug" "$node_name Labels: " "$label"
}

list_worker_node(){
    worker_number=0
    for i in `kubectl get node |grep -v NAME |cut -f1 -d " "`
    do
        if [[ $i != $local_ipaddress ]]; then
            if [[ $i != $local_hostname ]]; then
                get_node $i
                worker_number=`expr $worker_number + 1`
            fi
        fi
    done
    if [[ $worker_number < 2 ]]; then
        log "summary" "Worker node number [$worker_number] is not enough. At least 2 worker nodes are required."
    fi
}

list_master_node(){
    for i in `kubectl get node |grep -v NAME |cut -f1 -d " "`
    do
        if [[ $i == $local_ipaddress ]]; then
                get_node $i
        else if [[ $i == $local_hostname ]]; then
                get_node $i
            fi
        fi
    done
}

function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

list_os_version(){
    kernal=`uname -r`
    log "info" "OS kernal: $kernal"
#-------------------------------Linux System Release-------------------------------------------------
    release=`cat /etc/system-release`
    log "info" "OS release version: $release"
#----------------------------------------------------------------------------------------------------
    kernal_version=`echo $kernal | awk 'BEGIN{FS="-"}{print $1}'`
    kernal_version_min=`echo $kernal | awk 'BEGIN{FS="-"}{print $2}' | awk 'BEGIN{FS="."}{print $1}'`
    design_version=3.10.0
    design_verion_min=514
    if version_gt $design_version $kernal_version; then
        log "summary" "Current OS kernal ${kernal_version} is not updated. Please update it to ${design_version}"
    elif version_gt $design_verion_min $kernal_version_min; then
        log "summary" "Current OS kernal patch ${kernal_version}-${kernal_version_min} is not updated. Please update it to ${design_version}-${design_verion_min}"
    fi
}

list_node_type(){
    log "info" "Current system: $NodeType"
    if [[ $is_nfs_server == true ]]; then
        log "info" "Current system: NFS server"
    fi
}

list_k8s_info(){
    log "info" "Kubernets Home: $K8S_HOME"
    log "info" "CDF version   : `cat $K8S_HOME/version.txt`"
}

list_nfs_home(){
    if [[ $is_nfs_server == true ]]; then
        log "info" "NFS Home      : $NFS_SERVER"
    fi
}

lookup(){
  if hash nslookup 2>/dev/null; then
    log "debug" "nslookup $local_hostname" "`nslookup $local_hostname`"
    log "debug" "nslookup www.google.com" "`nslookup www.google.com`"
  fi
}

list_system_details(){
    net_mask=`ifconfig |grep $local_ipaddress|awk 'BEGIN{FS=" "}{print $4}'`
    broadcast=`ifconfig |grep $local_ipaddress|awk 'BEGIN{FS=" "}{print $6}'`
    cpu_core=`cat /proc/cpuinfo |grep processor |wc -l`
    mem_info=`cat /proc/meminfo  |grep Mem`
    mem_info_freeh=`free -h|grep -v Swap`
    #cpu_frq=`cat /proc/cpuinfo | grep name | cut -f9 -d " " | uniq |awk 'BEGIN{FS="GHz"}{print $1}'`
    #cpu_type=`cat /proc/cpuinfo | grep name | cut -f3 -d " " | uniq `
    cpu_frq=`cat /proc/cpuinfo | grep "model name" | cut -f2 -d "@" | uniq |awk 'BEGIN{FS="GHz"}{print $1}'`
    cpu_type=`cat /proc/cpuinfo | grep "model name" | uniq | cut -f2 -d ":"| cut -f1 -d "@"`
    cpu_version=`cat /proc/cpuinfo | grep name | cut -f6 -d " " | uniq |awk 'BEGIN{FS="-"}{print $1}'`
    cpu_version_all=`cat /proc/cpuinfo | grep name | cut -f6 -d " " | uniq`
    cpu_version_min=`cat /proc/cpuinfo | grep name | cut -f6 -d " " | uniq |awk 'BEGIN{FS="-"}{print $1}'|awk 'BEGIN{FS="E"}{print $2}'`

    read des gateway genmask <<<　`route |sed -n '3p'`

    log "debug" "List gateway" "`route`"
    log "debug" "`cat /proc/cpuinfo | grep name | uniq`"
    log "info" "Local  IP:      $local_ipaddress"
    log "info" "Netmask  :      $net_mask"
    log "info" "Broadcast:      $broadcast"
    log "info" "Gateway  :      $gateway"
    log "info" "CPU cores:      $cpu_core"
    log "debug" "Check Memory    $mem_info"
    checkDisk
    # 4 CPU cores is mandatory
    if version_gt 4 $cpu_core; then
        log "summary" "CPU Cores($cpu_core) is not enough. 8 core CPU is required."
    fi
    net_mask_ip=`echo $net_mask | awk 'BEGIN{FS="."}{print $4}'`
    #net mask cannot be 255.255.255.255
    if [[ $net_mask_ip == 255 ]]; then
        log "summary" "net_mask is not correct. It cannot be $net_mask"
    fi
    #16 GB memroy is necessary
    memory_size=`cat /proc/meminfo  |grep MemTotal | cut -f8 -d " "`
    if version_gt 16000000 $memory_size; then
        log "summary" "Memory size($memory_size kb) is not enough. 32 GB is necessary."
    fi
    #CPU frequency should be larger than 2.20
    if version_gt 2.20 $cpu_frq; then
      log "summary" "CPU frequency (${cpu_frq}GHz) is not as expected. Use 2.3 GHz or above."
    fi
    #CPU type
    if [[ $cpu_type != Intel\(R\) ]]; then
      log "summary" "CPU type is $cpu_type. Please use Intel(R) CPU."
    fi

    #CPU version
    if [[ $cpu_version != E5 ]] && [[ $cpu_version != E6 ]] && [[ $cpu_version != E7 ]]; then
        log "summary" "CPU processor is ${cpu_version_all}. Please use E5 or above."
    fi

    lookup
    log "debug" "Check /etc/host info:" "`cat /etc/hosts`"
}

check_all_service(){
    check_service firewalld
    check_service kubelet.service
    check_service docker-bootstrap.service
    check_service docker.service
    check_service chronyd.service
    if [[ $is_nfs_server == "true" ]]; then
        check_service rpcbind
    fi

}

check_uid(){
    if [[ $is_nfs_server == true ]]; then
        userid=`getent passwd | grep 1999|awk 'BEGIN{FS=":"}{print $1}'`
        uid=`getent passwd | grep 1999|awk 'BEGIN{FS=":"}{print $3}'`
        gid=`getent passwd | grep 1999|awk 'BEGIN{FS=":"}{print $4}'`
        log "info" "Userid:         $userid"
        log "info" "Uid:            $uid"
        log "info" "Gid:            $gid"
        if [[ $uid != 1999 ]]; then
            log "summary" "User 1999(itsma) is not defined in this system."
            userid=1999
        fi
    fi
}

check_nfs_folder(){
    if [[ $is_nfs_server = true ]]; then
        for i in `showmount --exports |grep -v "Export list" |cut -f1 -d " "`
        do
            if [[ -z $i ]]; then
                log "Error" "NFS folder $i does not exist"
            else
                uuid=`ls -ld $i | cut -f3 -d " "`
                ggid=`ls -ld $i | cut -f4 -d " "`
                log "info" "Checking $i uid:gid: $uuid:$ggid"
                if [[ $uuid != $userid ]]; then
                    log "summary" "Ownership of NFS server $i is not correct!"
                fi
            fi
        done
    fi
}

get_namespace(){
    NAMESPACE=`kubectl get namespace |grep itsma | cut -f1 -d " "`
}

check_deployer_status(){
   name_space=$1
   if [[ ! -z $name_space ]]; then
        log "info" "Checking deployer pod status under namespace [$name_space]"
        for i in `kubectl get pods -n $name_space  |grep -v Running |grep -v NAME | grep controller |grep -v Terminating | cut -f1 -d " "`
        do
            read NAME STATE status other <<< "`kubectl get pods $i -n $name_space |grep -v NAME`"
            log "debug" "$name_space     $NAME           $STATE      $status"
            echo -ne "."
            if [[ $status != Completed ]]; then
                log "summary" "Deployer pod(${NAME}) is not correct($status). Run 'kubectl logs $i -n $name_space' for details."
                log "debug" "kubectl logs $i -n $name_space" "`kubectl logs $i -n $name_space`"
            fi
        done
        log "info" ""
    fi
}

get_pvc(){
  podname=$1
  pvc=`kubectl describe pods ${podname} -n ${name_space} |grep "ClaimName" |awk 'begin{FS=":"}{print $2}'`
}

get_pv(){
  podname=$1
  get_pvc $podname
  pv=`kubectl describe pvc -n ${name_space} ${pvc} | grep "Volume:" | awk 'begin{FS=":"}{print $2}'`
}

get_nfs_volume(){
  podname=$1
  get_pv ${podname}
  nfs_volume_path=`kubectl describe pv ${pv} |grep "Path:" | awk 'begin{FS=":"}{print $2}'`
  nfs_volume_server=`kubectl describe pv ${pv} |grep "Server:" | awk 'begin{FS=":"}{print $2}'`
}

get_configmap(){
  cm_folder=${log_folder}/configmap_${name_space}
  mkdir -p ${cm_folder}
  if [ ! "$(ls -A ${cm_folder})" ]; then
    for cm in `kubectl get cm -n ${name_space} |grep -v NAME| cut -f1 -d " "`
    do
      touch ${cm_folder}/$cm
      kubectl get cm -n ${name_space} $cm -o yaml > ${cm_folder}/$cm
    done
  fi
}

get_log_files(){
  podname=$1
  containername=$2
  get_nfs_volume ${podname}
  mkdir -p /tmp/nfs_tmp
  mount -t nfs ${nfs_volume_server}:${nfs_volume_path}/logs /tmp/nfs_tmp
  found=`find /tmp/nfs_tmp -name ${podname}* | wc -l`
  found1=`kubectl describe pod -n ${name_space} ${podname} |grep ":" | grep "/var/log" | awk 'begin{FS=":"}{print $2}' | wc -l`
  found2=`kubectl describe pod -n ${name_space} ${podname} | grep "/log" | awk 'begin{FS=":"}{print $1}' | wc -l`
  if [ "${found}" -ge "1" ]; then
    mkdir -p ${log_path}/${podname}
    for found_path in `find /tmp/nfs_tmp -name ${podname}*`
    do
      if [ -d ${found_path} ] && [ "$(ls -A ${found_path})" ]; then
        cp -R ${found_path} ${log_path}/${podname}
      else
        cp ${found_path} ${log_path}/${podname}
      fi
    done
  elif [ "${found1}" -ge "1" ]; then
     mkdir -p ${log_path}/${podname}
     for found_path in `kubectl describe pod -n ${name_space} ${podname} |grep ":" | grep "/var/log" | awk 'begin{FS=":"}{print $2}'`
     do
       kubectl cp -n ${name_space} -c ${containername} ${podname}:${found_path} ${log_path}/${podname}
     done
  elif [ "${found2}" -ge "1" ]; then
      mkdir -p ${log_path}/${podname}
      for found_path in `kubectl describe pod -n ${name_space} ${podname} | grep "/log" | awk 'begin{FS=":"}{print $1}'`
      do
        kubectl cp -n ${name_space} -c ${containername} ${podname}:${found_path} ${log_path}/${podname}
      done
  fi
  umount /tmp/nfs_tmp
  rm -rf /tmp/nfs_tmp
}

check_pod_status(){
   name_space=$1
   if [[ ! -z $name_space ]]; then
        log "info" "Checking pod status under namespace [$name_space]"
        log "debug" "`kubectl get pods -n $name_space -o wide`"
        for i in `kubectl get pods -n $name_space |grep -v NAME | grep -v Terminating | cut -f1 -d " "`
        do
            read NAME STATE status restart_number other <<< "`kubectl get pods $i -n $name_space |grep -v NAME`"
            desired_status=`echo $STATE | awk 'BEGIN{FS="/"}{print $2}'`
            actual_status=`echo $STATE | awk 'BEGIN{FS="/"}{print $1}'`
            log "debug" "$name_space     $NAME           $STATE      $status      $restart_number"
            echo -ne "."
            if [[ $status != Running ]] && [[ $status != Completed ]] && [[ $status != Terminating ]] ; then
                get_configmap
                container_id=`kubectl describe pod $i -n $name_space | sed -n '/Container\ ID/{x;p};h' | grep -v install | grep -v vault |grep -v throttling | grep -v dependency| sed 's/://g' | sed 's/\ \ //g'`
                log "summary" "pod(${NAME}) is not correct($status). Run 'kubectl describe pods $i -n $name_space' for details."
                log "debug" "kubectl describe pods $i -n $name_space" "`kubectl describe pods $i -n $name_space`"
                if [[ ${name_space} == core ]]; then
                  log "cmd" "kubectl describe pod $i -n $name_space" "`kubectl describe pod $i -n $name_space > ${log_folder}/${name_space}_${i}_describe.log`"
                else
                  log "cmd" "kubectl describe pod $i -n $name_space" "`kubectl describe pod $i -n $name_space > ${log_folder}/${name_space}_${i}_describe.log`"
                  if [[ -d ${log_path}/${i} ]]; then
                    log "cmd" "move file to folder" "`mv ${log_folder}/${name_space}_${i}_describe.log ${log_path}/${i}`"
                  fi
                fi
            elif [[ $desired_status != $actual_status ]] && [[ $status != Completed ]] && [[ $status != Terminating ]]; then
                get_configmap
                for container_id in `kubectl describe pod $i -n $name_space | sed -n '/Container\ ID/{x;p};h' | grep -v install | grep -v vault |grep -v throttling | grep -v dependency| grep -v dependence|sed 's/://g' | sed 's/\ \ //g'`
                do
                  if [[ ${name_space} != core ]]; then
                    get_log_files $i $container_id
                  fi
                  log "summary" "pod(${NAME}) is not ready($STATE). Run 'kubectl logs $i -n $name_space -c $container_id' "
                  log "debug" "kubectl describe pods $i -n $name_space" "`kubectl describe pods $i -n $name_space`"
                  if [[ ${name_space} == core ]]; then
                    log "cmd" "kubectl describe pod $i -n $name_space" "`kubectl describe pod $i -n $name_space > ${log_folder}/${name_space}_${i}_describe.log`"
                    log "cmd" "kubectl logs $i -n $name_space -c $container_id" "`kubectl logs $i -n $name_space -c $container_id > ${log_folder}/${name_space}_${i}_log.log`"
                  else
                    log "cmd" "kubectl describe pod $i -n $name_space" "`kubectl describe pod $i -n $name_space > ${log_folder}/${name_space}_${i}_describe.log`"
                    log "cmd" "kubectl logs $i -n $name_space -c $container_id" "`kubectl logs $i -n $name_space -c $container_id > ${log_folder}/${name_space}_${i}_log.log`"
                    if [[ -d ${log_path}/${i} ]]; then
                      log "cmd" "move describe file to destination" "`mv ${log_folder}/${name_space}_${i}_describe.log ${log_path}/${i}`"
                      log "cmd" "move log file to destination" "`mv ${log_folder}/${name_space}_${i}_log.log ${log_path}/${i}`"
                    fi
                  fi
                done
            fi
      			if version_gt $restart_number 50; then
      				log "summary" "pod(${NAME}) was restarted too many times($restart_number). Current status is $status($STATE)"
      			fi
        done
        log "info" ""
    fi
}


#------------------------------------------------------------------------------------------------------
check_suite_db(){
suite_db_type=`kubectl get cm database-configmap -n $1 -o yaml|grep bo_db_type|cut -f2 -d ":"`
suite_db_version=`pwd`
}

check_suite_info(){
suite_size=`kubectl get cm -n $1 itsma-common-configmap -o yaml|grep itom_suite_size|cut -f2 -d ":"`
suite_mode=`kubectl get cm -n $1 itsma-common-configmap -o yaml|grep itom_suite_mode|cut -f2 -d ":"`
suite_version=`kubectl get cm -n $1 itsma-common-configmap -o yaml|grep itom_suite_version|cut -f2 -d ":"`
}
#------------------------------------------------------------------------------------------------------

summary(){
    if [[ $NodeType == Master ]]; then
        list_os_version
        list_k8s_info
        list_nfs_home
        list_node_type
        list_system_details
        check_uid
        list_master_node
        list_worker_node
        check_nfs_folder
        check_all_service
        check_deployer_status $NAMESPACE
        check_pod_status core
        check_pod_status $NAMESPACE
#------------------------------------------------------------------------------------------------------
        check_suite_db $NAMESPACE
	check_suite_info $NAMESPACE
#------------------------------------------------------------------------------------------------------
    elif [[ $NodeType == Worker ]]; then
        list_os_version
        list_k8s_info
        list_nfs_home
        list_node_type
        list_system_details
        check_uid
        check_nfs_folder
        check_all_service
    elif [[ $NodeType == NFS ]]; then
        list_os_version
        list_nfs_home
        list_node_type
        list_system_details
        check_uid
        check_nfs_folder
        check_service rpcbind
    else
        list_os_version
        list_system_details
    fi
}

checkAll(){
    log "begin" "################### Start ##################"
    check_k8s_home
    checkNFSExports
    check_is_master
    get_namespace
    summary
    log "end" "################### END ##################"
    if [[ -f ${logfile}_tmp ]]; then
        while IFS= read -r var
        do
            echo -e "${Yellow} $var ${NC}"
            echo -e "${Yellow} $var ${NC}" >> $logfile
        done < ${logfile}_tmp
        rm -rf ${logfile}_tmp
    fi
    if [ "$(ls -A ${log_path})" ]; then
        cd ${ab_path}
        mv ${logfile} ${log_path}
        tar -czf ${log_path}.tar.gz ${log_folder}
        rm -rf ${log_path}
        echo  "All results are under ${log_path}.tar.gz, please provide this package to MF Support"
    else
        rm -rf ${log_path}
        cd ${ab_path}
        tar -czf ${logfile}.tar.gz $(basename ${logfile})
        rm -rf ${logfile}
        echo "System is running well, result is under ${logfile}.tar.gz"
    fi
}

#------------------------------------------------------------------------------------------

checktemplates(){
while [ "$1" != "" ]; do
     if [[ -f $1 ]]; then
         log_check "debug" "we can find the template $1"
     else
	 log_check "error" "we cannot find the template $1"
     fi
shift 1
done
}

readsplittemplate(){
while [ "$1" != "" ]; do
	while IFS='' read -r line || [[ -n "$line" ]]; do
	  IFS=':' read -r wholeline <<< "$line"
	  IFS='.' read -r number content <<< "$wholeline"
	  log_check "debug" "we are reading $content in the template $1"
	  readwritecontent "$content" $number
	done < "$1"
shift 1
done
}

readwritecontent(){
	case $1 in 
		"OS") echo "$2.$1:$kernal"+"$release" >> $hardware_info 
   		echo  $3 >> $hardware_info
		log_check "debug" "we are writing OS info: $kernal + $release information to the $hardware_info file";;
		"CPU model") echo "$2.$1:this machine has a $cpu_type CPU" >> $hardware_info 
		echo  $3 >> $hardware_info
		log_check "debug" "we are writing CPU type info: $cpu_type CPU model information to the $hardware_info file";;
		"CPU cores") echo "$2.$1:this is a $cpu_core cores CPU"  >> $hardware_info
		echo  $3 >> $hardware_info 
		log_check "debug" "we are writing CPU cores info: $cpu_core cores to the $hardware_info file";;
		"Memory") echo "$2.$1:this is the Memory info:" >> $hardware_info
		echo "$mem_info_freeh" >> $hardware_info
		echo  $3 >> $hardware_info 
		log_check "debug" "we are writing Memory info to the $hardware_info file"
		log_check "debug" "$mem_info_freeh";;
		"Free space") echo "$2.$1:there is free space $available_disk GB" >> $hardware_info 
		echo  $3 >> $hardware_info
		log_check "debug" "we are writing Free space info: $available_disk GB to the $hardware_info file";;
		"Database Type") echo "$2.$1:this suite configured with a $suite_db_type database" >> $hardware_info 
		echo  $3 >> $hardware_info
		log_check "debug" "we are writing Database Type info: $suite_db_type to the $hardware_info file";;
		"Database Version") echo "$2.$1:this is the Database Version" >> $hardware_info 
		echo  $3 >> $hardware_info
		log_check "debug" "we are writing Database Version information to the $hardware_info file";;
		"SMA mode") echo "$2.$1:SMA mode: $suite_mode" >> $k8s_info 
		echo  $3 >> $k8s_info
		log_check "debug" "we are writing SMA mode information: $suite_mode to the $k8s_info file";;
		"SMA version") echo "$2.$1:SMA version: $suite_version" >> $k8s_info 
		echo  $3 >> $k8s_info
		log_check "debug" "we are writing SMA version information $suite_version to the $k8s_info file";;
		"SMA profile") echo "$2.$1:SMA profile: $suite_size" >> $k8s_info 
		echo  $3 >> $k8s_info
		log_check "debug" "we are writing SMA profile information: $suite_size to the $k8s_info file";;
		"NFS") echo "$2.$1:NFS Server: $nfs_volume_server" >> $k8s_info 
		echo  $3 >> $k8s_info
		log_check "debug" "we are writing NFS information: $nfs_volume_server to the $k8s_info file";;
		"Kubernetes get node") echo "$2.$1:this is the result of kubectl get node:" >> $k8s_info 
		echo -e "`kubectl get node`" >> $k8s_info
		echo  $3 >> $k8s_info
		log_check "debug" "we are writing Kubernetes get node information to the $k8s_info file"
		log_check "debug" "`kubectl get node`";;
		"Kubernetes top node") echo "$2.$1:this is the results of kubectl top node:" >> $k8s_info 
		echo -e "`kubectl top node`" >> $k8s_info
		echo  $3 >> $k8s_info
		log_check "debug" "we are writing Kubernetes top node information to the $k8s_info file"
		log_check "debug" "`kubectl top node`" ;;
		"Kubernetes get pod") echo "$2.$1:this is the result of kubectl get pods:" >> $k8s_info 
		echo -e "`kubectl get pods --all-namespaces -o wide --show-all`" >> $k8s_info
		echo  $3 >> $k8s_info
		log_check "debug" "we are writing Kubernetes get pod information to the $k8s_info file"
		log_check "debug" "`kubectl get pods --all-namespaces -o wide --show-all`";;
	esac
}

checkList(){
      echo "################### Check List Generating ... ##################"
      checktemplates "$CURRENTPATH/hardware_template" "$CURRENTPATH/K8S_template"
      readsplittemplate "$CURRENTPATH/hardware_template" "$CURRENTPATH/K8S_template"
      echo "#################### Check List Completed ######################"
      if [ -d $checklist_folder ]; then
        cd ${checklist_folder}
        mv ${checklistfile} ${hardware_info} ${k8s_info} ${checklist_folder}
        tar -czf ${checklist_folder}.tar.gz ${checklist_folder}
        rm -rf ${checklist_folder}
        echo  "All check list results are under ${checklist_folder}.tar.gz, please provide this package to MF Support"
      fi
}

source /etc/profile
checkAll
checkList