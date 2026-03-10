.PHONY: check check-python check-shell

check: check-python check-shell

check-python:
	python3 -m py_compile aduc_for_linux.py

check-shell:
	bash -n install.sh
