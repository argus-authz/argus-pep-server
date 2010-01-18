#! /bin/bash

# This script starts and stop the PEP daemon.

HOME="$(cd "${0%/*}/.." && pwd)"
CONF="$HOME/conf/pepd.ini"

# Source our environment setup script
. $HOME/sbin/env.sh

# Add the PDP home directory property
JVMOPTS="-Dorg.glite.authz.pep.home=$HOME $JVMOPTS"

function executeAdminCommand {
    HOST=`sed 's/ //g' $CONF | grep "^adminHost" | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z $HOST ] ; then
       HOST="127.0.0.1"
    fi

    PORT=`sed 's/ //g' $CONF | grep "^adminPort" | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z $PORT ] ; then
       PORT="8155"
    fi
    
    PASS=`sed 's/ //g' $CONF | grep "^adminPassword" | awk 'BEGIN {FS="="}{print $2}'`
    
    
    $JAVACMD $JVMOPTS 'org.glite.authz.common.http.JettyAdminServiceCLI' $HOST $PORT $1 $PASS
}

function start {
    # Run the PDP
    $JAVACMD $JVMOPTS 'org.glite.authz.pep.server.PEPDaemon' $CONF &
}


function print_help {
   echo "PEP Daemon control script"
   echo ""
   echo "Usage:"
   echo "  $0 start   - to start the service"
   echo "  $0 stop    - to stop the service" 
   echo "  $0 status  - print PEP daemon status"
   echo "  $0 clearResponseCache - clears the PEP daemon PDP response cache"
   echo ""
}

if [ $# -lt 1 ] ; then
   print_help
   exit 0
fi

case "$1" in
  'start') start;;
  'stop') executeAdminCommand 'shutdown' ;;
  'status') executeAdminCommand 'status' ;;
  'clearResponseCache') executeAdminCommand 'clearResponseCache' ;;
  *) print_help ;;
esac
