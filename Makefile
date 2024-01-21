protos:
	protoc -I=pb --go_out=pb --go_opt=paths=source_relative pb/models.proto

build:
	$(eval RUST_LIB_PATH=$(shell go list -m -f "{{.Dir}}" github.com/project-illium/ilxd))
	chmod -R u+w $(RUST_LIB_PATH)
	cd $(RUST_LIB_PATH)/crypto/rust && cargo build --release
	cd $(RUST_LIB_PATH)/zk/rust && cargo build --release
	chmod -R u-w $(RUST_LIB_PATH)
