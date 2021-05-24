##
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
##

name=argus-pep-server

version=1.7.5

prefix=/

maven_settings_file=project/maven-settings.xml

tmp_dir=$(CURDIR)/tmp

.PHONY: clean dist package install

all: package

clean:
	rm -rf target $(tmp_dir) *.tar.gz

dist:
	@echo "Package the sources..."
	test ! -d $(tmp_dir) || rm -fr $(tmp_dir)
	mkdir -p $(tmp_dir)/$(name)-$(version)
	cp Makefile README.md pom.xml $(tmp_dir)/$(name)-$(version)
	cp -r project $(tmp_dir)/$(name)-$(version)
	cp -r doc $(tmp_dir)/$(name)-$(version)
	cp -r src $(tmp_dir)/$(name)-$(version)
	test ! -f $(name)-$(version).tar.gz || rm $(name)-$(version).tar.gz
	tar -C $(tmp_dir) -czf $(name)-$(version).tar.gz $(name)-$(version)
	rm -fr $(tmp_dir)

package:
	@echo "Build package with maven"
	mvn -B -U package


install:
	@echo "Install binary in $(DESTDIR)$(prefix)"
	test -f target/$(name)-$(version).tar.gz
	mkdir -p $(DESTDIR)$(prefix)
	tar -C $(DESTDIR)$(prefix) -xvzf target/$(name)-$(version).tar.gz


mvn_install:
	@echo "Install in local maven repository"
	mvn -B -s $(maven_settings_file) install
