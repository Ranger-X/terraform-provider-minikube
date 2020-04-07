TEST?="./minikube"
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)
WEBSITE_REPO=github.com/Ranger-X/terraform-provider-minikube
PKG_NAME=minikube
MINIKUBE_PKG_PATH=$(GOPATH)/pkg/mod/k8s.io/minikube@v1.9.2
KUBERNETES_VERSION=0.17.3

default: build

build: pkg/minikube/assets/assets.go pkg/minikube/translate/translations.go fmtcheck
	go install

test: fmtcheck
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

website:
ifeq (,$(wildcard $(GOPATH)/src/$(WEBSITE_REPO)))
	echo "$(WEBSITE_REPO) not found in your GOPATH (necessary for layouts and assets), get-ting..."
	git clone https://$(WEBSITE_REPO) $(GOPATH)/src/$(WEBSITE_REPO)
endif
	@$(MAKE) -C $(GOPATH)/src/$(WEBSITE_REPO) website-provider PROVIDER_PATH=$(shell pwd) PROVIDER_NAME=$(PKG_NAME)

website-test:
ifeq (,$(wildcard $(GOPATH)/src/$(WEBSITE_REPO)))
	echo "$(WEBSITE_REPO) not found in your GOPATH (necessary for layouts and assets), get-ting..."
	git clone https://$(WEBSITE_REPO) $(GOPATH)/src/$(WEBSITE_REPO)
endif
	@$(MAKE) -C $(GOPATH)/src/$(WEBSITE_REPO) website-provider-test PROVIDER_PATH=$(shell pwd) PROVIDER_NAME=$(PKG_NAME)

# Regenerates assets.go when template files have been updated
pkg/minikube/assets/assets.go: $(shell find "$(MINIKUBE_PKG_PATH)/deploy/addons" -type f)
	which go-bindata || GO111MODULE=off GOBIN="$(GOPATH)$(DIRSEP)bin" go get github.com/jteeuwen/go-bindata/...
	chmod u+w -R $(MINIKUBE_PKG_PATH)/pkg
	PATH="$(PATH)$(PATHSEP)$(GOPATH)$(DIRSEP)bin" cd $(MINIKUBE_PKG_PATH) && go-bindata -nomemcopy -o $@ -pkg assets deploy/addons/...
	-gofmt -s -w $(MINIKUBE_PKG_PATH)/$@
	@#golint: Dns should be DNS (compat sed)
	@sed -i -e 's/Dns/DNS/g' $(MINIKUBE_PKG_PATH)/$@ && rm -f $(MINIKUBE_PKG_PATH)/-e
	@#golint: Html should be HTML (compat sed)
	@sed -i -e 's/Html/HTML/g' $(MINIKUBE_PKG_PATH)/$@ && rm -f $(MINIKUBE_PKG_PATH)/-e

pkg/minikube/translate/translations.go: $(shell find "$(MINIKUBE_PKG_PATH)/translations/" -type f)
	which go-bindata || GO111MODULE=off GOBIN="$(GOPATH)$(DIRSEP)bin" go get github.com/jteeuwen/go-bindata/...
	chmod u+w -R $(MINIKUBE_PKG_PATH)/pkg
	PATH="$(PATH)$(PATHSEP)$(GOPATH)$(DIRSEP)bin" cd $(MINIKUBE_PKG_PATH) && go-bindata -nomemcopy -o $@ -pkg translate translations/...
	-gofmt -s -w $(MINIKUBE_PKG_PATH)/$@
	@#golint: Json should be JSON (compat sed)
	@sed -i -e 's/Json/JSON/' $(MINIKUBE_PKG_PATH)/$@ && rm -f $(MINIKUBE_PKG_PATH)/-e

.PHONY: build test testacc vet fmt fmtcheck errcheck test-compile website website-test

