.PHONY: check check-python check-shell build-deb

check: check-python check-shell

check-python:
	python3 -m py_compile aduc_for_linux.py

check-shell:
	bash -n install.sh
	bash -n scripts/build_deb.sh
	bash -n packaging/debian/DEBIAN/postinst
	bash -n packaging/debian/DEBIAN/prerm

build-deb:
	./scripts/build_deb.sh
