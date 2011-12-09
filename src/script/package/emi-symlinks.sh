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

function create_symlink(){
	if [ -e $2 ]; then
		rm -rf $2
	fi
	ln -vs $1 $2
}
# pepdctl: /usr/sbin/pepdctl -> /usr/share/argus/pepd/sbin/pepdctl
create_symlink ../../usr/share/argus/$NAME/sbin/$NAMECTL usr/sbin/$NAMECTL

# conf: /usr/share/argus/pepd/conf -> /etc/argus/pepd
create_symlink $root_prefix/etc/argus/$NAME $HOME/conf

# lib: /usr/share/argus/pepd/lib -> /var/lib/argus/pepd/lib
create_symlink $root_prefix/var/lib/argus/$NAME/lib $HOME/lib

# logs: /usr/share/argus/pepd/logs -> /var/log/argus/pepd
create_symlink $root_prefix/var/log/argus/$NAME $HOME/logs

# doc: /usr/share/argus/pepd/doc -> /usr/share/doc/argus/pepd
create_symlink $root_prefix/usr/share/doc/argus/$NAME $HOME/doc

