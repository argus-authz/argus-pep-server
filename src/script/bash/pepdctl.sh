#! /bin/bash

# This script starts and stop the PDP daemon.

# PDP home directory
HOME="$(cd "${0%/*}/.." && pwd)"

# Source our environment setup script
. $HOME/bin/env.sh

function start {        
    # Add the PDP home directory property
    JVMOPTS="-Dorg.glite.authz.pep.home=$HOME $JVMOPTS"
    
    # Run the PDP
    $JAVACMD $JVMOPTS 'org.glite.authz.pep.server.PEPDaemon' $HOME/conf/pepd.ini &
}

function stop {
    curl --connect-timeout 3 --max-time 5 -s --show-error http://127.0.0.1:8155/shutdown
    ECODE=$?
    if [ "$ECODE" != 0 ] ; then
       echo "Shutdown failed.  curl returned error code of" $ECODE
    fi
}

function print_help {
   echo "PEP Daemon start/stop script"
   echo ""
   echo "Usage:"
   echo "  pepdctl.sh start   - to start the service"
   echo "  pepdctl.sh stop    - to stop the service" 
   echo ""
}

if [ $# -lt 1 ] ; then
   print_help
   exit 0
fi

case "$1" in
  'start') start;;
  'stop') stop;;
  *) print_help ;;
esac