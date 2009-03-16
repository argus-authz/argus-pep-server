#! /bin/bash

# This script starts and stop the PEP daemon.

HOME="$(cd "${0%/*}/.." && pwd)"
CONF="$HOME/conf/pepd.ini"

# Source our environment setup script
. $HOME/bin/env.sh

function start {        
    # Add the PDP home directory property
    JVMOPTS="-Dorg.glite.authz.pep.home=$HOME $JVMOPTS"
    
    # Run the PDP
    $JAVACMD $JVMOPTS 'org.glite.authz.pep.server.PEPDaemon' $CONF &
}

function stop {
    SPORT=`grep shutdownPort $CONF | sed 's/ //g' | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z "$SPORT" ]; then
      SPORT=8155
    fi
    
    curl --connect-timeout 3 --max-time 5 -s --show-error http://127.0.0.1:$SPORT/shutdown
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
