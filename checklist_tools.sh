#!/usr/bin/env bash

#------------------parameter definitions---------------------------#
CURRENTPATH=$(cd "$(dirname "$0")"; pwd)
SYSTEMCHECKSCRIPT=$CURRENTPATH/system_check.sh
HARDWARETEMPLATE=$CURRENTPATH/hardware_template
K8STEMPLATE=$CURRENTPATH/K8S_template
FILEDATE=`date "+%Y%m%d%H%M%S"`
CHECKLOGFILE=/tmp/checklist_${FILEDATE}.log
#global machines=([""]="")

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

#------------------read and splite the template---------------------------#
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

includescripts(){
if [[ "$?" == "0" ]]; then
	source "$1" > /dev/null	
fi
}


#------------------------List all nodes and DB&NFS-----------------------#
listallmachines(){
	nodes=`kubectl get nodes|grep -v NAME|cut -d " " -f1`
	printf "$nodes\n"
	#machines=(["NFS Server host"="$NFS_SERVER"])
}

#------------------ssh connect to other nodes---------------------------#
connectnode(){
	printf "This is a test"
}
file_date

check_list(){
printf "*********************Check List Report is Generating************************************\n"
checkfile $SYSTEMCHECKSCRIPT $HARDWARETEMPLATE $K8STEMPLATE #check the system_check scripts/hardware templates/k8s templates
source $SYSTEMCHECKSCRIPT > /dev/null #include the system_check.sh parameters & functions
printf "$file_date\n"
printf "$local_ipaddress\n"
printf "*********************Check List Report is Completed************************************\n"
}

check_list
