#!/bin/bash
#
# Copyright (c) Members of the EGEE Collaboration. 2006-2009.
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

set -e

NAME=pepd
HOME="usr/share/argus/${NAME}"
NAMECTL="${NAME}ctl"


root_prefix="../../../.."

create_symlink () {
	if [ -e $2 ]; then
		rm -vrf $2
	fi
	ln -vs $1 $2
}

# DEBUG
ls -l $HOME

# pdpctl: /usr/sbin/pdpctl -> /usr/share/argus/pdp/sbin/pdpctl
mkdir -vp usr/sbin
create_symlink ../../usr/share/argus/$NAME/sbin/$NAMECTL usr/sbin/$NAMECTL

# conf: /usr/share/argus/pdp/conf -> /etc/argus/pdp
create_symlink $root_prefix/etc/argus/$NAME $HOME/conf

# lib: /usr/share/argus/pdp/lib -> /var/lib/argus/pdp/lib
create_symlink $root_prefix/var/lib/argus/$NAME/lib $HOME/lib

# logs: /usr/share/argus/pdp/logs -> /var/log/argus/pdp
create_symlink $root_prefix/var/log/argus/$NAME $HOME/logs

# doc: /usr/share/argus/pdp/doc -> /usr/share/doc/argus/pdp
create_symlink $root_prefix/usr/share/doc/argus/$NAME $HOME/doc

