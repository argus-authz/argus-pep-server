#! /bin/bash
#
# Copyright (c) Members of the EGEE Collaboration. 2006-2010.
# See http://www.eu-egee.org/partners/ for details on the copyright holders.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

JAVACMD=`which java`
if [ ! -x "$JAVACMD" ] ; then
  echo "Error: 'java' not available in command path"
  exit
fi

# add in the dependency .jar files from the lib directory
LIBDIR="$HOME/lib"
LIBS="$LIBDIR/*.jar"
for i in $LIBS
do
    # if the directory is empty, then it will return the input string
    # this is stupid, so case for it
    if [ -f "$i" ] ; then
        LOCALCLASSPATH="$LOCALCLASSPATH":"$i"
    fi
done
#JVMOPTS="-Djava.net.preferIPv4Stack=true $JVMOPTS"
JVMOPTS="-Djava.endorsed.dirs=$HOME/lib/endorsed -classpath $LOCALCLASSPATH $JVMOPTS"
