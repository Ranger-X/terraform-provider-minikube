TEST?="./minikube"
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)
WEBSITE_REPO=github.com/Ranger-X/terraform-provider-minikube
PKG_NAME=minikube
MINIKUBE_VERSION=v1.9.2
MINIKUBE_ISO_VERSION=v1.9.0
KUBERNETES_VERSION=0.17.3
RELEASE_VERSION=v0.9.2
RELEASE_DIR=releases
GOARCH?=amd64
BINARY=terraform-provider-minikube_${RELEASE_VERSION}_x4
LINUX_RELEASE=terraform-provider-minikube_${RELEASE_VERSION}_linux_${GOARCH}
MAC_RELEASE=terraform-provider-minikube_${RELEASE_VERSION}_darwin_${GOARCH}
STAGE_DIR?=${RELEASE_DIR}

default: build

deps: fmt
	go install

build: assets_hack linux mac stage

test: deps fmtcheck
	go test $(TEST) || exit 1
	echo $(TEST) | \
		xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

testacc: fmtcheck
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

vet:
	@echo "go vet ."
	@go vet $$(go list ./... | grep -v vendor/) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Vet found suspicious constructs. Please check the reported constructs"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi

fmt:
	gofmt -w $(GOFMT_FILES)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'  $(KUBERNETES_VERSION)"

errcheck:
	@sh -c "'$(CURDIR)/scripts/errcheck.sh'"

test-compile:
	@if [ "$(TEST)" = "./..." ]; then \
		echo "ERROR: Set TEST to a specific package. For example,"; \
		echo "  make test-compile TEST=./$(PKG_NAME)"; \
		exit 1; \
	fi
	go test -c $(TEST) $(TESTARGS)

assets_hack: deps fmtcheck
	chmod u+w -R ${GOPATH}/pkg/mod/k8s.io/minikube@${MINIKUBE_VERSION}
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -nomemcopy \
		-prefix "${GOPATH}/pkg/mod/k8s.io/minikube@${MINIKUBE_VERSION}/" \
		-o ${GOPATH}/pkg/mod/k8s.io/minikube@${MINIKUBE_VERSION}/pkg/minikube/assets/assets.go \
		-pkg assets ${GOPATH}/pkg/mod/k8s.io/minikube@${MINIKUBE_VERSION}/deploy/addons/...

clean:
	rm -rf "${RELEASE_DIR}"
	rm ${LINUX_RELEASE} ${MAC_RELEASE} ${LINUX_RELEASE}.zip ${MAC_RELEASE}.zip

linux: deps fmtcheck assets_hack
	GOOS=linux GOARCH=${GOARCH} go build --ldflags="-X k8s.io/minikube/pkg/version.isoVersion=${MINIKUBE_ISO_VERSION}" -o "${BINARY}"
	zip "${LINUX_RELEASE}.zip" "${BINARY}"
	rm "${BINARY}" && mkdir -p "${RELEASE_DIR}"
	mv "${LINUX_RELEASE}.zip" "${RELEASE_DIR}"

mac: deps fmtcheck assets_hack
	GOOS=darwin GOARCH=${GOARCH} go build --ldflags="-X k8s.io/minikube/pkg/version.isoVersion=${MINIKUBE_ISO_VERSION}" -o "${BINARY}"
	zip "${MAC_RELEASE}.zip" "${BINARY}"
	rm "${BINARY}" && mkdir -p "${RELEASE_DIR}"
	mv "${MAC_RELEASE}.zip" "${RELEASE_DIR}"

stage: deps fmtcheck assets_hack
	GOOS=linux GOARCH=${GOARCH} go build --ldflags="-X k8s.io/minikube/pkg/version.isoVersion=${MINIKUBE_ISO_VERSION}" -o "${STAGE_DIR}/${BINARY}"

# Regenerates assets.go when template files have been updated
#pkg/minikube/assets/assets.go: $(shell find "$(MINIKUBE_PKG_PATH)/deploy/addons" -type f)
#	which go-bindata || GO111MODULE=off GOBIN="$(GOPATH)$(DIRSEP)bin" go get github.com/jteeuwen/go-bindata/...
#	chmod u+w -R $(MINIKUBE_PKG_PATH)/pkg
#	PATH="$(PATH)$(PATHSEP)$(GOPATH)$(DIRSEP)bin" cd $(MINIKUBE_PKG_PATH) && go-bindata -nomemcopy -o $@ -pkg assets deploy/addons/...
#	-gofmt -s -w $(MINIKUBE_PKG_PATH)/$@
#	@#golint: Dns should be DNS (compat sed)
#	@sed -i -e 's/Dns/DNS/g' $(MINIKUBE_PKG_PATH)/$@ && rm -f $(MINIKUBE_PKG_PATH)/-e
#	@#golint: Html should be HTML (compat sed)
#	@sed -i -e 's/Html/HTML/g' $(MINIKUBE_PKG_PATH)/$@ && rm -f $(MINIKUBE_PKG_PATH)/-e
#
#pkg/minikube/translate/translations.go: $(shell find "$(MINIKUBE_PKG_PATH)/translations/" -type f)
#	which go-bindata || GO111MODULE=off GOBIN="$(GOPATH)$(DIRSEP)bin" go get github.com/jteeuwen/go-bindata/...
#	chmod u+w -R $(MINIKUBE_PKG_PATH)/pkg
#	PATH="$(PATH)$(PATHSEP)$(GOPATH)$(DIRSEP)bin" cd $(MINIKUBE_PKG_PATH) && go-bindata -nomemcopy -o $@ -pkg translate translations/...
#	-gofmt -s -w $(MINIKUBE_PKG_PATH)/$@
#	@#golint: Json should be JSON (compat sed)
#	@sed -i -e 's/Json/JSON/' $(MINIKUBE_PKG_PATH)/$@ && rm -f $(MINIKUBE_PKG_PATH)/-e

.PHONY: build test testacc vet fmt fmtcheck errcheck test-compile website website-test

