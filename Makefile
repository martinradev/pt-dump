
all: pt_lib interface
	echo "pt_dump_lib and pt_dump_py installed"

pt_lib:
	cd pt_dump_lib && \
	cargo build --release

interface: pt_lib
	cd pt_dump_py && \
	maturin build --release && \
	find $(basename $(CURDIR))/pt_dump_py/target/wheels -name pt_dump_py*.whl | xargs pip3 install --force-reinstall

