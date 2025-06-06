.PHONY: test-unit
test-unit:
	pip install ./python\[test\]
	pytest ./python/kubeflow/trainer/api/trainer_client_test.py

.PHONY: test-unit-with-coverage
test-unit-with-coverage:
	pip install ./python\[test\]

	coverage run --source=kubeflow.trainer.api.trainer_client,kubeflow.trainer.utils.utils -m pytest ./python/kubeflow/trainer/api/trainer_client_test.py
	coverage report -m kubeflow/trainer/api/trainer_client.py kubeflow/trainer/utils/utils.py
	coverage html
