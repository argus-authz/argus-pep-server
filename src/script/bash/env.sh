#! /bin/bash

# This script sets up the environment used to execute the service.
# The environment variable JAVA_HOME must be set before execution
# of this script and must point to an installed JDK or JRE.
#
# Optional, the environment variable JVMOPTS may be used to pass
# arguments to the JVM used to execute the service.



# The absolute path of the 'java' command used to execute the service
declare JAVACMD

# Local variable holding arguments passed to the JVM at startup time
declare JVMOPTS

# Classpath used to execute the service.  This is independent of the 
# system classpath so that it neither influences, nor is influenced
# by, system-wide settings.
declare LOCALCLASSPATH


if [ -z "$JAVA_HOME" ] ; then
  echo "ERROR: JAVA_HOME environment variable is not set."
  exit
else
  if [ -x "$JAVA_HOME/jre/sh/java" ] ; then 
    # IBM's JDK on AIX uses strange locations for the executables
    JAVACMD="$JAVA_HOME/jre/sh/java"
  else
    JAVACMD="$JAVA_HOME/bin/java"
  fi
fi

if [ ! -x "$JAVACMD" ] ; then
  echo "Error: JAVA_HOME is not defined correctly."
  echo "  We cannot execute $JAVACMD"
  exit
fi

LOCALCLASSPATH="$JAVA_HOME/lib/tools.jar:$JAVA_HOME/lib/classes.zip"

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

JVMOPTS="-Djava.endorsed.dirs=$HOME/lib/endorsed -classpath $LOCALCLASSPATH"