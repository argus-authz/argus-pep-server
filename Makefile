name=argus-pep-server
spec=fedora/$(name).spec
version=$(shell grep "Version:" $(spec) | sed -e "s/Version://g" -e "s/[ \t]*//g")
release=1
rpmbuild_dir=$(shell pwd)/rpmbuild
settings_file=project/emi-maven-settings.xml
stage_dir=$(shell pwd)/stage
prefix=/

.PHONY: etics package clean rpm

all: package rpm

clean:	
	rm -rf target $(rpmbuild_dir) stage tgz RPMS $(spec)

spec:
	sed -e 's#@@BUILD_SETTINGS@@# #g' $(spec).in > $(spec)

package: spec
	mvn -B package

spec-etics:
	sed -e 's#@@BUILD_SETTINGS@@#-s $(settings_file)#g' $(spec).in > $(spec)

package-etics: spec-etics
	mvn -B -s $(settings_file) package

rpm: package
	@echo "Building RPM in $(rpmbuild_dir)"
	mkdir -p $(rpmbuild_dir)/BUILD $(rpmbuild_dir)/RPMS \
		$(rpmbuild_dir)/SOURCES $(rpmbuild_dir)/SPECS \
		$(rpmbuild_dir)/SRPMS
	cp target/$(name)-$(version).src.tar.gz $(rpmbuild_dir)/SOURCES/$(name)-$(version).tar.gz
	rpmbuild --nodeps -v -ba $(spec) --define "_topdir $(rpmbuild_dir)"

install:
	@echo "Install binary in $(DESTDIR)$(prefix)"
	test -f target/$(name)-$(version).tar.gz
	mkdir -p $(DESTDIR)$(prefix)
	tar -C $(DESTDIR)$(prefix) -xvzf target/$(name)-$(version).tar.gz

etics:
	@echo "Publising RPMs and tarballs"
	test -f $(rpmbuild_dir)/SRPMS/$(name)-$(version)-*.src.rpm
	mkdir -p tgz RPMS
	cp target/*.tar.gz tgz
	cp -r $(rpmbuild_dir)/RPMS/* $(rpmbuild_dir)/SRPMS/* RPMS

stage:
	@echo "Staging tarball in $(stage_dir)"
	mkdir -p $(stage_dir)
	tar -C $(stage_dir) -xvzf target/$(name)-$(version).tar.gz
