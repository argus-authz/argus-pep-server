#! /bin/bash

# This script sets up the environment used to execute the service.
#
# Optional, the environment variable JVMOPTS may be used to pass
# arguments to the JVM used to execute the service.

# Classpath used to execute the service.  This is independent of the 
# system classpath so that it neither influences, nor is influenced
# by, system-wide settings.
declare LOCALCLASSPATH

JAVACMD=`which java`
if [ ! -x "$JAVACMD" ] ; then
  echo "Error: 'java' not available in command path"
  exit
fi

# add in the dependency .jar files from the lib directory
LIBDIR="$HOME/lib"
LIBS="$LIBDIR/*.ja"r
for i in $LIBS
do
    # if the directory is empty, then it will return the input string
    # this is stupid, so case for it
    if [ "$i" != "${LIBS}" ] ; then
        LOCALCLASSPATH="$LOCALCLASSPATH":"$i"
    fi
done

JVMOPTS="-Djava.endorsed.dirs=$HOME/lib/endorsed -classpath $LOCALCLASSPATH $JVMOPTS"