# Copyright 2025 The Kubeflow Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Unit tests for the TrainerClient class in the Kubeflow Trainer SDK.

This module uses pytest and unittest.mock to simulate Kubernetes API interactions.
It tests TrainerClient's behavior across job listing, resource creation etc
"""
import datetime
import multiprocessing
import random
import string
import uuid
from dataclasses import asdict
from typing import Optional
from unittest.mock import Mock, patch

import kubeflow.trainer.models as models
import pytest
from kubeflow.trainer import TrainerClient
from kubeflow.trainer.constants import constants
from kubeflow.trainer.types import types
from kubeflow.trainer.utils import utils

# --------------------------
# Constants for test scenarios
# --------------------------
TIMEOUT = "timeout"
RUNTIME = "runtime"
INVALID_RUNTIME = "invalid_runtime"
SUCCESS = "success"
FAILED = "Failed"
CREATED = "Created"
RUNNING = "Running"
RESTARTING = "Restarting"
NO_PODS = "no_pods"
SUCCEEDED = "Succeeded"
INVALID = "invalid"
DEFAULT_NAMESPACE = "default"
PYTORCH = "pytorch"
MOCK_POD_OBJ = "mock_pod_obj"
FAIL_LOGS = "fail_logs"
TORCH_DISTRIBUTED = "torch-distributed"
LIST_RUNTIMES = "list_runtimes"
BASIC_TRAIN_JOB_NAME = "basic-job"
TRAIN_JOB_WITH_BUILT_IN_TRAINER = "train-job-with-built-in-trainer"
TRAIN_JOB_WITH_CUSTOM_TRAINER = "train-job-with-custom-trainer"


# --------------------------
# Fixtures
# --------------------------


@pytest.fixture
def training_client(request):
    """Provide a TrainerClient with mocked Kubernetes APIs."""
    with patch(
        "kubernetes.client.CustomObjectsApi",
        return_value=Mock(
            create_namespaced_custom_object=Mock(side_effect=conditional_error_handler),
            patch_namespaced_custom_object=Mock(side_effect=conditional_error_handler),
            delete_namespaced_custom_object=Mock(side_effect=conditional_error_handler),
            get_namespaced_custom_object=Mock(
                side_effect=get_namespaced_custom_object_response
            ),
            get_cluster_custom_object=Mock(
                side_effect=get_cluster_custom_object_response
            ),
            list_namespaced_custom_object=Mock(
                side_effect=list_namespaced_custom_object_response
            ),
            list_cluster_custom_object=Mock(side_effect=list_cluster_custom_object),
        ),
    ), patch(
        "kubernetes.client.CoreV1Api",
        return_value=Mock(
            list_namespaced_pod=Mock(side_effect=list_namespaced_pod_response),
            read_namespaced_pod_log=Mock(side_effect=mock_read_namespaced_pod_log),
        ),
    ):
        yield TrainerClient()


# --------------------------
# Mock Handlers
# --------------------------


def conditional_error_handler(*args, **kwargs):
    """Raise simulated errors based on resource name."""
    if args[2] == TIMEOUT:
        raise multiprocessing.TimeoutError()
    elif args[2] == RUNTIME:
        raise RuntimeError()


def list_namespaced_pod_response(*args, **kwargs):
    """Return mock pod list response."""
    pod_list = get_mock_pod_list()
    mock_thread = Mock()
    mock_thread.get.return_value = pod_list
    return mock_thread


def get_mock_pod_list():
    """Create a mocked Kubernetes PodList object with pods for different training steps."""
    return models.IoK8sApiCoreV1PodList(
        items=[
            # Dataset initializer pod
            models.IoK8sApiCoreV1Pod(
                metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(
                    name="dataset-initializer-pod",
                    namespace=DEFAULT_NAMESPACE,
                    labels={
                        constants.JOBSET_NAME_LABEL: BASIC_TRAIN_JOB_NAME,
                        constants.JOBSET_RJOB_NAME_LABEL: constants.DATASET_INITIALIZER,
                        constants.JOB_INDEX_LABEL: "0",
                    },
                ),
                spec=models.IoK8sApiCoreV1PodSpec(
                    containers=[
                        models.IoK8sApiCoreV1Container(
                            name=constants.DATASET_INITIALIZER,
                            image="dataset-initializer:latest",
                            command=["python", "-m", "dataset_initializer"],
                        )
                    ]
                ),
                status=models.IoK8sApiCoreV1PodStatus(phase="Running"),
            ),
            # Model initializer pod
            models.IoK8sApiCoreV1Pod(
                metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(
                    name="model-initializer-pod",
                    namespace=DEFAULT_NAMESPACE,
                    labels={
                        constants.JOBSET_NAME_LABEL: BASIC_TRAIN_JOB_NAME,
                        constants.JOBSET_RJOB_NAME_LABEL: constants.MODEL_INITIALIZER,
                        constants.JOB_INDEX_LABEL: "0",
                    },
                ),
                spec=models.IoK8sApiCoreV1PodSpec(
                    containers=[
                        models.IoK8sApiCoreV1Container(
                            name=constants.MODEL_INITIALIZER,
                            image="model-initializer:latest",
                            command=["python", "-m", "model_initializer"],
                        )
                    ]
                ),
                status=models.IoK8sApiCoreV1PodStatus(phase="Running"),
            ),
            # Training node pod
            models.IoK8sApiCoreV1Pod(
                metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(
                    name="node-0-pod",
                    namespace=DEFAULT_NAMESPACE,
                    labels={
                        constants.JOBSET_NAME_LABEL: BASIC_TRAIN_JOB_NAME,
                        constants.JOBSET_RJOB_NAME_LABEL: constants.NODE,
                        constants.JOB_INDEX_LABEL: "0",
                    },
                ),
                spec=models.IoK8sApiCoreV1PodSpec(
                    containers=[
                        models.IoK8sApiCoreV1Container(
                            name=constants.NODE,
                            image="trainer:latest",
                            command=["python", "-m", "trainer"],
                            resources=get_resource_requirements(),
                        )
                    ]
                ),
                status=models.IoK8sApiCoreV1PodStatus(phase="Running"),
            ),
        ]
    )


def get_resource_requirements() -> models.IoK8sApiCoreV1ResourceRequirements:
    """Create a mock ResourceRequirements object for testing."""
    return models.IoK8sApiCoreV1ResourceRequirements(
        requests={
            "nvidia.com/gpu": models.IoK8sApimachineryPkgApiResourceQuantity("1"),
            "memory": models.IoK8sApimachineryPkgApiResourceQuantity("2Gi"),
        },
        limits={
            "nvidia.com/gpu": models.IoK8sApimachineryPkgApiResourceQuantity("1"),
            "memory": models.IoK8sApimachineryPkgApiResourceQuantity("4Gi"),
        },
    )


def add_custom_trainer_to_job(
    train_job: models.TrainerV1alpha1TrainJob,
) -> models.TrainerV1alpha1TrainJob:
    """
    Add a custom trainer configuration to the train job.
    """
    trainer_crd = models.TrainerV1alpha1Trainer(
        command=["bash", "-c"],
        args=[
            '\nif ! [ -x "$(command -v pip)" ]; then\n    python -m ensurepip '
            "|| python -m ensurepip --user || apt-get install python-pip"
            "\nfi\n\nPIP_DISABLE_PIP_VERSION_CHECK=1 python -m pip install --quiet"
            "         --no-warn-script-location --index-url https://pypi.org/simple "
            "torch numpy \n\nread -r -d '' SCRIPT << EOM\n\nfunc=lambda: "
            'print("Hello World"),  # Simple hello world function\n\n<lambda>('
            "{'learning_rate': 0.001, 'batch_size': 32})\n\nEOM\nprintf \"%s\" "
            '"$SCRIPT" > "trainer_client_test.py"\ntorchrun "trainer_client_test.py"'
        ],
        num_nodes=2,
    )

    train_job.spec.trainer = trainer_crd
    return train_job


def add_built_in_trainer_to_job(
    train_job: models.TrainerV1alpha1TrainJob,
) -> models.TrainerV1alpha1TrainJob:
    """
    Add a built-in trainer configuration to the train job.
    """
    trainer_crd = models.TrainerV1alpha1Trainer(
        args=["batch_size=2", "epochs=2", "loss=Loss.CEWithChunkedOutputLoss"],
        command=["tune", "run"],
        numNodes=2,
    )
    train_job.spec.trainer = trainer_crd
    return train_job


def get_train_job(
    train_job_name: str = BASIC_TRAIN_JOB_NAME,
    runtime_name: str = TORCH_DISTRIBUTED,
    add_built_in_trainer: bool = False,
    add_custom_trainer: bool = False,
) -> models.TrainerV1alpha1TrainJob:
    """
    Create a mock TrainJob object with optional trainer configurations.
    """
    train_job = models.TrainerV1alpha1TrainJob(
        apiVersion=constants.API_VERSION,
        kind=constants.TRAINJOB_KIND,
        metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(name=train_job_name),
        spec=models.TrainerV1alpha1TrainJobSpec(
            runtimeRef=models.TrainerV1alpha1RuntimeRef(name=runtime_name),
        ),
    )

    if add_built_in_trainer:
        train_job = add_built_in_trainer_to_job(train_job)
    if add_custom_trainer:
        train_job = add_custom_trainer_to_job(train_job)

    return train_job


def get_cluster_custom_object_response(*args, **kwargs):
    """Return a mocked ClusterTrainingRuntime object."""
    if args[3] == TIMEOUT:
        raise multiprocessing.TimeoutError()
    if args[3] == RUNTIME:
        raise RuntimeError()
    if args[2] == constants.CLUSTER_TRAINING_RUNTIME_PLURAL:
        result = create_cluster_training_runtime()

    result = normalize_model(result, models.TrainerV1alpha1ClusterTrainingRuntime)
    mock_thread = Mock()
    mock_thread.get.return_value = result
    return mock_thread


def get_namespaced_custom_object_response(*args, **kwargs):
    """Return a mocked TrainJob object."""
    if args[2] == TIMEOUT or args[4] == TIMEOUT:
        raise multiprocessing.TimeoutError()
    if args[2] == RUNTIME or args[4] == RUNTIME:
        raise RuntimeError()
    if args[3] == "trainjobs":  # TODO: review this.
        job = add_status(create_train_job(train_job_name=args[4]))

    mock_thread = Mock()
    mock_thread.get.return_value = job
    return mock_thread


def add_status(
    train_job: models.TrainerV1alpha1TrainJob,
) -> models.TrainerV1alpha1TrainJob:
    """
    Add status information to the train job.
    """
    # Set initial status to Created
    status = models.TrainerV1alpha1TrainJobStatus(
        conditions=[
            models.IoK8sApimachineryPkgApisMetaV1Condition(
                type="Complete",
                status="True",
                lastTransitionTime=datetime.datetime.now(),
                reason="JobCompleted",
                message="Job completed successfully",
            )
        ]
    )
    train_job.status = status
    return train_job


def list_namespaced_custom_object_response(*args, **kwargs):
    """Return a list of mocked TrainJob objects."""
    mock_thread = Mock()

    if args[2] == TIMEOUT:
        raise multiprocessing.TimeoutError()
    if args[2] == RUNTIME:
        raise RuntimeError()
    if args[2] == "basic-job":
        return_value = {"items": [create_train_job(train_job_name="basic-job")]}
    if args[3] == "trainjobs":
        return_value = build_train_job_list()

    mock_thread.get.return_value = return_value
    return mock_thread


def build_train_job_list() -> models.TrainerV1alpha1TrainJobList:
    """Build a mock TrainJobList object with multiple TrainJob items."""
    train_job_list = models.TrainerV1alpha1TrainJobList(
        apiVersion=constants.API_VERSION,
        kind=constants.TRAINJOB_PLURAL,
        items=[
            add_status(create_train_job(train_job_name="basic-job-1")),
            add_status(create_train_job(train_job_name="basic-job-2")),
        ],
    )
    return normalize_model(train_job_list, models.TrainerV1alpha1TrainJobList)


def list_cluster_custom_object(*args, **kwargs):
    """Return a generic mocked response for cluster object listing."""
    if args[2] == TIMEOUT:
        raise multiprocessing.TimeoutError()
    if args[2] == RUNTIME:
        raise RuntimeError()
    if args[2] == constants.CLUSTER_TRAINING_RUNTIME_PLURAL:
        items = [
            create_cluster_training_runtime(name="runtime-1"),
            create_cluster_training_runtime(name="runtime-2"),
        ]

    runtime_list_obj = models.TrainerV1alpha1ClusterTrainingRuntimeList(items=items)
    runtimes = normalize_model(
        runtime_list_obj, models.TrainerV1alpha1ClusterTrainingRuntimeList
    )

    mock_thread = Mock()
    mock_thread.get.return_value = runtimes
    return mock_thread


def mock_read_namespaced_pod_log(*args, **kwargs):
    """Simulate log retrieval from a pod."""
    if kwargs.get("namespace") == FAIL_LOGS:
        raise Exception("Failed to read logs")
    return "test log content"


def normalize_model(model_obj, model_class):
    # Simulate real api behavior
    # Converts model to raw dictionary, like a real API response
    # Parses dict and ensures correct model instantiation and type validation
    return model_class.from_dict(model_obj.to_dict())


# --------------------------
# Object Creators
# --------------------------


def create_train_job(
    train_job_name: str = random.choice(string.ascii_lowercase) + uuid.uuid4().hex[:11],
    namespace: str = "default",
    runtime: str = PYTORCH,
    image: str = "pytorch/pytorch:latest",
    initializer: Optional[types.Initializer] = None,
    command: list = None,
    args: list = None,
) -> models.TrainerV1alpha1TrainJob:
    """Create a mock TrainJob object."""
    return models.TrainerV1alpha1TrainJob(
        apiVersion=constants.API_VERSION,
        kind=constants.TRAINJOB_KIND,
        metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(
            name=train_job_name,
            namespace=namespace,
            creationTimestamp=datetime.datetime(2025, 6, 1, 10, 30, 0),
        ),
        spec=models.TrainerV1alpha1TrainJobSpec(
            runtimeRef=models.TrainerV1alpha1RuntimeRef(name=runtime),
            trainer=None,
            initializer=(
                models.TrainerV1alpha1Initializer(
                    dataset=utils.get_dataset_initializer(initializer.dataset),
                    model=utils.get_model_initializer(initializer.model),
                )
                if initializer
                else None
            ),
        ),
    )


def create_cluster_training_runtime(
    namespace: str = "default",
    name: str = TORCH_DISTRIBUTED,
) -> models.TrainerV1alpha1ClusterTrainingRuntime:
    """Create a mock ClusterTrainingRuntime object."""
    runtime = models.TrainerV1alpha1ClusterTrainingRuntime(
        apiVersion=constants.API_VERSION,
        kind="ClusterTrainingRuntime",
        metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(
            name=name,
            namespace=namespace,
            labels={
                "trainer.kubeflow.org/accelerator": "gpu-tesla-v100-16gb",
            },
        ),
        spec=models.TrainerV1alpha1TrainingRuntimeSpec(
            mlPolicy=models.TrainerV1alpha1MLPolicy(
                torch=models.TrainerV1alpha1TorchMLPolicySource(
                    num_proc_per_node=models.IoK8sApimachineryPkgUtilIntstrIntOrString(
                        2
                    )
                ),
                numNodes=2,
            ),
            template=models.TrainerV1alpha1JobSetTemplateSpec(
                metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(
                    name=name,
                    namespace=namespace,
                ),
                spec=models.JobsetV1alpha2JobSetSpec(
                    replicated_jobs=[get_replicated_job()]
                ),
            ),
        ),
    )
    return runtime


def get_replicated_job() -> models.TrainerV1alpha1ClusterTrainingRuntime:
    return models.JobsetV1alpha2ReplicatedJob(
        name="node",
        replicas=1,
        template=models.IoK8sApiBatchV1JobTemplateSpec(
            metadata=models.IoK8sApimachineryPkgApisMetaV1ObjectMeta(
                labels={"trainer.kubeflow.org/trainjob-ancestor-step": "trainer"}
            ),
            spec=models.IoK8sApiBatchV1JobSpec(
                template=models.IoK8sApiCoreV1PodTemplateSpec(
                    spec=models.IoK8sApiCoreV1PodSpec(containers=[get_container()])
                )
            ),
        ),
    )


def get_container() -> models.IoK8sApiCoreV1Container:
    return models.IoK8sApiCoreV1Container(
        name="node",
        image="image",
        command=["echo", "Hello World"],
        resources=get_resource_requirements(),
    )


def create_runtime_type(
    name: str = TORCH_DISTRIBUTED,
) -> types.Runtime:
    """Create a mock Runtime object for testing."""
    return types.Runtime(
        name=name,
        pretrained_model=None,
        trainer=types.Trainer(
            trainer_type=types.TrainerType.CUSTOM_TRAINER,
            framework=types.Framework.TORCH,
            entrypoint=[constants.TORCH_ENTRYPOINT],
            accelerator="gpu-tesla-v100-16gb",
            accelerator_count=4,
        ),
    )


def get_train_job_data_type(
    train_job_name: str = BASIC_TRAIN_JOB_NAME,
) -> types.TrainJob:
    """Create a mock TrainJob object with the expected structure for testing.

    Args:
        train_job_name: Name of the training job

    Returns:
        A TrainJob object with predefined structure for testing
    """
    return types.TrainJob(
        name=train_job_name,
        creation_timestamp=datetime.datetime(2025, 6, 1, 10, 30, 0),
        runtime=types.Runtime(
            name=TORCH_DISTRIBUTED,
            pretrained_model=None,
            trainer=types.Trainer(
                trainer_type=types.TrainerType.CUSTOM_TRAINER,
                framework=types.Framework.TORCH,
                entrypoint=["torchrun"],
                accelerator="gpu-tesla-v100-16gb",
                accelerator_count=4,
            ),
        ),
        steps=[
            types.Step(
                name="dataset-initializer",
                status="Running",
                pod_name="dataset-initializer-pod",
                device="Unknown",
                device_count="Unknown",
            ),
            types.Step(
                name="model-initializer",
                status="Running",
                pod_name="model-initializer-pod",
                device="Unknown",
                device_count="Unknown",
            ),
            types.Step(
                name="node-0",
                status="Running",
                pod_name="node-0-pod",
                device="gpu",
                device_count="1",
            ),
        ],
        status="Succeeded",
    )


# --------------------------
# Test Scenarios
# --------------------------

test_data_list_jobs = [
    (
        "valid flow with all defaults",
        {},
        SUCCESS,
        [
            get_train_job_data_type(train_job_name="basic-job-1"),
            get_train_job_data_type(train_job_name="basic-job-2"),
        ],
    ),
    ("timeout error when listing jobs", {"namespace": TIMEOUT}, FAILED, TimeoutError),
    ("runtime error when listing jobs", {"namespace": RUNTIME}, FAILED, RuntimeError),
]

test_data_get_runtime = [
    ("valid flow with all defaults", {}, SUCCESS, create_runtime_type()),
    (
        "timeout error when getting runtime",
        {
            "name": TIMEOUT,
        },
        FAILED,
        TimeoutError,
    ),
    (
        "runtime error when getting runtime",
        {
            "name": RUNTIME,
        },
        FAILED,
        RuntimeError,
    ),
]

test_data_list_runtimes = [
    (
        "valid flow with all defaults",
        {
            "name": LIST_RUNTIMES,
        },
        SUCCESS,
        [create_runtime_type(name="runtime-1"), create_runtime_type(name="runtime-2")],
    ),
]

test_data_train = [
    (
        "valid flow with all defaults",
        {},
        DEFAULT_NAMESPACE,
        SUCCESS,
        get_train_job(train_job_name=BASIC_TRAIN_JOB_NAME),
    ),
    (
        "valid flow with built in trainer",
        {
            "trainer": types.BuiltinTrainer(
                config=types.TorchTuneConfig(
                    num_nodes=2,
                    batch_size=2,
                    epochs=2,
                    loss=types.Loss.CEWithChunkedOutputLoss,
                )
            )
        },
        DEFAULT_NAMESPACE,
        SUCCESS,
        get_train_job(
            train_job_name=TRAIN_JOB_WITH_BUILT_IN_TRAINER, add_built_in_trainer=True
        ),
    ),
    (
        "valid flow with custom trainer",
        {
            "trainer": types.CustomTrainer(
                func=lambda: print("Hello World"),  # Simple hello world function
                func_args={"learning_rate": 0.001, "batch_size": 32},
                packages_to_install=["torch", "numpy"],
                pip_index_url=constants.DEFAULT_PIP_INDEX_URL,
                num_nodes=2,
            )
        },
        DEFAULT_NAMESPACE,
        SUCCESS,
        get_train_job(
            train_job_name=TRAIN_JOB_WITH_CUSTOM_TRAINER, add_custom_trainer=True
        ),
    ),
    ("timeout error when deleting job", {}, TIMEOUT, FAILED, TimeoutError),
    ("runtime error when deleting job", {}, RUNTIME, FAILED, RuntimeError),
]

test_data_get_job = [
    (
        "valid flow with all defaults",
        {"name": BASIC_TRAIN_JOB_NAME},
        SUCCESS,
        get_train_job_data_type(train_job_name=BASIC_TRAIN_JOB_NAME),
    ),
    ("timeout error when getting job", {"name": TIMEOUT}, FAILED, TimeoutError),
    ("runtime error when getting job", {"name": RUNTIME}, FAILED, RuntimeError),
]

test_data_delete_job = [
    ("valid flow with all defaults", {"name": BASIC_TRAIN_JOB_NAME}, SUCCESS, None),
    ("timeout error when deleting job", {"namespace": TIMEOUT}, FAILED, TimeoutError),
    ("runtime error when deleting job", {"namespace": RUNTIME}, FAILED, RuntimeError),
]

test_data_get_job_logs = [
    (
        "valid flow with all defaults",
        {"name": BASIC_TRAIN_JOB_NAME},
        SUCCESS,
        {
            "node-0": "test log content",
        },
    ),
    ("runtime error when getting logs", {"name": RUNTIME}, FAILED, RuntimeError),
]


# --------------------------
# Tests
# --------------------------


@pytest.mark.parametrize(
    "test_name,kwargs,expected_status,expected_response", test_data_get_runtime
)
def test_get_runtime(
    training_client, test_name, kwargs, expected_status, expected_response
):
    """Test TrainerClient.get_runtime with basic success path."""
    print("Executing test:", test_name)
    try:
        runtime = training_client.get_runtime(kwargs.get("name", TORCH_DISTRIBUTED))

        assert expected_status == SUCCESS
        assert isinstance(runtime, types.Runtime)
        assert asdict(runtime) == asdict(expected_response)

    except Exception as e:
        assert type(e) is expected_response
    print("test execution complete")


@pytest.mark.parametrize(
    "test_name,kwargs,expected_status,expected_response", test_data_list_runtimes
)
def test_list_runtimes(
    training_client, test_name, kwargs, expected_status, expected_response
):
    print("Executing test:", test_name)
    try:
        training_client.namespace = kwargs.get("namespace", DEFAULT_NAMESPACE)
        runtimes = training_client.list_runtimes()

        assert expected_status == SUCCESS
        assert isinstance(runtimes, list)
        assert all(isinstance(r, types.Runtime) for r in runtimes)
        assert [asdict(r) for r in runtimes] == [asdict(r) for r in expected_response]

    except Exception as e:
        assert type(e) is expected_response
    print("test execution complete")


@pytest.mark.parametrize(
    "test_name,kwargs,namespace,expected_status,expected_output", test_data_train
)
def test_train(
    training_client, test_name, kwargs, namespace, expected_status, expected_output
):
    """Test TrainerClient.list_runtimes with basic success path."""
    print("Executing test:", test_name)
    try:
        training_client.namespace = namespace
        train_job_name = training_client.train(**kwargs)

        assert expected_status == SUCCESS

        # This is to get around the fact that the train job name is dynamically generated
        # In the future name generation may be more deterministic, and we can revisit this approach
        expected_output.metadata.name = train_job_name

        training_client.custom_api.create_namespaced_custom_object.assert_called_with(
            constants.GROUP,
            constants.VERSION,
            DEFAULT_NAMESPACE,
            constants.TRAINJOB_PLURAL,
            expected_output.to_dict(),
        )

    except Exception as e:
        assert type(e) is expected_output
    print("test execution complete")


@pytest.mark.parametrize(
    "test_name,kwargs,expected_status,expected_response", test_data_get_job
)
def test_get_job(
    training_client, test_name, kwargs, expected_status, expected_response
):
    """Test TrainerClient.list_runtimes with basic success path."""
    print("Executing test:", test_name)
    try:
        job = training_client.get_job(**kwargs)

        assert expected_status == SUCCESS
        assert asdict(job) == asdict(expected_response)

    except Exception as e:
        assert type(e) is expected_response
    print("test execution complete")


@pytest.mark.parametrize(
    "test_name,kwargs,expected_status,expected_response", test_data_list_jobs
)
def test_list_jobs(
    training_client, test_name, kwargs, expected_status, expected_response
):
    """Test TrainerClient.list_jobs with basic success path."""
    print("Executing test:", test_name)
    try:
        training_client.namespace = kwargs.get("namespace", DEFAULT_NAMESPACE)
        jobs = training_client.list_jobs()

        assert expected_status == SUCCESS
        assert isinstance(jobs, list)
        assert len(jobs) == 2

    except Exception as e:
        assert type(e) is expected_response
    print("test execution complete")


@pytest.mark.parametrize(
    "test_name,kwargs,expected_status,expected_response", test_data_delete_job
)
def test_delete_job(
    training_client, test_name, kwargs, expected_status, expected_response
):
    """Test TrainerClient.list_runtimes with basic success path."""
    print("Executing test:", test_name)
    try:
        training_client.namespace = kwargs.get("namespace", DEFAULT_NAMESPACE)
        training_client.delete_job(kwargs.get("name"))
        assert expected_status == SUCCESS

        training_client.custom_api.delete_namespaced_custom_object.assert_called_with(
            constants.GROUP,
            constants.VERSION,
            kwargs.get("namespace", DEFAULT_NAMESPACE),
            constants.TRAINJOB_PLURAL,
            name=kwargs.get("name"),
        )

    except Exception as e:
        assert type(e) is expected_response
    print("test execution complete")


@pytest.mark.parametrize(
    "test_name,kwargs,expected_status,expected_response", test_data_get_job_logs
)
def test_get_job_logs(
    training_client, test_name, kwargs, expected_status, expected_response
):
    """Test TrainerClient.list_runtimes with basic success path."""
    print("Executing test:", test_name)
    try:

        logs = training_client.get_job_logs(kwargs.get("name"))
        assert expected_status == SUCCESS
        assert logs == expected_response

    except Exception as e:
        assert type(e) is expected_response
    print("test execution complete")
