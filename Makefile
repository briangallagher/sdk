# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
LOCALBIN ?= $(PROJECT_DIR)/bin

# Tool versions
KIND_VERSION ?= v0.27.0
K8S_VERSION ?= 1.32.0

# Tool binaries
KIND ?= $(LOCALBIN)/kind

# Input and output location for Notebooks executed with Papermill.
NOTEBOOK_INPUT=$(PROJECT_DIR)/examples/training/pytorch/image-classification/mnist.ipynb
NOTEBOOK_OUTPUT=$(PROJECT_DIR)/artifacts/notebooks/trainer_output.ipynb
PAPERMILL_TIMEOUT=900

.PHONY: kind
kind: ## Download Kind binary if required.
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/kind@$(KIND_VERSION)

.PHONY: test-e2e-notebook
test-e2e-notebook: ## Run Jupyter Notebook with Papermill.
	NOTEBOOK_INPUT=$(NOTEBOOK_INPUT) NOTEBOOK_OUTPUT=$(NOTEBOOK_OUTPUT) PAPERMILL_TIMEOUT=$(PAPERMILL_TIMEOUT) ./hack/e2e-run-notebook.sh

.PHONY: test-e2e-setup-cluster
test-e2e-setup-cluster: kind ## Setup Kind cluster for e2e test.
	KIND=$(KIND) K8S_VERSION=$(K8S_VERSION) ./hack/e2e-setup-cluster.sh
