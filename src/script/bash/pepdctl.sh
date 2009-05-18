#! /bin/bash

# This script starts and stop the PEP daemon.

HOME="$(cd "${0%/*}/.." && pwd)"
CONF="$HOME/conf/pepd.ini"

# Source our environment setup script
. $HOME/bin/env.sh

function status {
    SHOST=`sed 's/ //g' $CONF | grep "^hostname" | awk 'BEGIN {FS="="}{print $2}'`
    SPORT=`sed 's/ //g' $CONF | grep "^port" | awk 'BEGIN {FS="="}{print $2}'`
    SPORTSSL=`sed 's/ //g' $CONF | grep "^enableSSL" | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z "$SPORT" ]; then
      SPORT=8154
    fi
    
    if [ -z "$SPORTSSL" ]; then
      SPORTSSL="false"
    fi
    
    $JAVACMD $JVMOPTS 'org.glite.authz.pep.server.PEPDaemonAdminCLI' "status" $SHOST $SPORT $SPORTSSL
}

function start {        
    # Add the PDP home directory property
    JVMOPTS="-Dorg.glite.authz.pep.home=$HOME $JVMOPTS"
    
    # Run the PDP
    $JAVACMD $JVMOPTS 'org.glite.authz.pep.server.PEPDaemon' $CONF &
}

function stop {
    SHOST="127.0.0.1"
    SPORT=`sed 's/ //g' $CONF | grep "^shutdownPort" | awk 'BEGIN {FS="="}{print $2}'`
    if [ -z "$SPORT" ]; then
      SPORT=8155
    fi
    
    $JAVACMD $JVMOPTS 'org.glite.authz.pep.server.PEPDaemonAdminCLI' "shutdown" $SHOST $SPORT
}

function print_help {
   echo "PEP Daemon control script"
   echo ""
   echo "Usage:"
   echo "  $0 status  - print PEP daemon status"
   echo "  $0 start   - to start the service"
   echo "  $0 stop    - to stop the service" 
   echo ""
}

if [ $# -lt 1 ] ; then
   print_help
   exit 0
fi

case "$1" in
  'status') status;;
  'start') start;;
  'stop') stop;;
  *) print_help ;;
esac
