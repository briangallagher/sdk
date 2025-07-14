# make test-unit will produce html coverage by default. Run with `make test-unit report=xml` to produce xml report.
.PHONY: test-unit
test-unit:
	pip install "./python[test]"
	coverage run --source=kubeflow.trainer.api.trainer_client,kubeflow.trainer.utils.utils -m pytest ./python/kubeflow/trainer/api/trainer_client_test.py
	coverage report -m kubeflow/trainer/api/trainer_client.py kubeflow/trainer/utils/utils.py
ifeq ($(report),xml)
	coverage xml
else
	coverage html
endif
