import pytest
import re
import os
import json
import shutil
import hachoir.core.config as hachoir_config

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
sample1 = dict(
    sid=1,
    metadata={},
    service_name='characterize',
    service_config={},
    fileinfo=dict(
        magic='ASCII text, with no line terminators',
        md5='1f09ecbd362fa0dfff88d4788e6f5df0',
        mime='text/plain',
        sha1='a649bf201cde05724e48f2d397a615b201be34fb',
        sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        size=19,
        type='unknown',
    ),
    filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
    min_classification='TLP:WHITE',
    max_files=501,  # TODO: get the actual value
    ttl=3600,
)


@pytest.fixture
def class_instance():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    try:
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)

        from characterize import Characterize
        yield Characterize()
    finally:
        # Delete the service_manifest.yml
        os.remove(temp_service_config_path)


class TestCharacterize:

    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    def test_start(self, class_instance):
        class_instance.start()
        assert hachoir_config.quiet is True

    @pytest.mark.parametrize("sample", [
        sample1
    ])
    def test_execute(self, class_instance, sample):
        # Imports required to execute the sample
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest

        # Creating the required objects for execution
        service_task = ServiceTask(sample1)
        task = Task(service_task)
        class_instance._task = task
        service_request = ServiceRequest(task)

        # Actually executing the sample
        class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding date in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the date
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        assert test_result_response == correct_result_response

    def test_parse_link(self, class_instance):
        # TODO: Once a repo is available for samples, we can test this method
        # class_instance.parse_lnk()
        pass

    def test_get_type_val(self):
        # TODO: Once a repo is available for samples, we can test this method
        # from characterize import get_type_val
        # get_type_val()
        pass

    def test_build_key(self):
        # TODO: Once a repo is available for samples, we can test this method
        # from characterize import build_key
        # build_key()
        pass
