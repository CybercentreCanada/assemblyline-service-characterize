import errno
import json
import os
from pathlib import Path

import pytest
from assemblyline.common.identify import fileinfo
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from cart import unpack_file

from characterize import Characterize

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SELF_LOCATION = os.environ.get("FULL_SELF_LOCATION", ROOT_DIR)
SAMPLES_LOCATION = os.environ.get("FULL_SAMPLES_LOCATION", None)


def find_sample(locations, sample):
    # Assume samples are carted
    sample = f"{sample}.cart"

    for location in locations:
        p = [path for path in Path(location).rglob(sample)]
        if len(p) == 1:
            return p[0]

    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), sample)


def list_results(location):
    return [f.rstrip(".json") for f in os.listdir(os.path.join(location, "tests", "results"))]


@pytest.fixture()
def sample(request):
    sample_path = find_sample(request.cls.locations, request.param)
    unpack_file(sample_path, os.path.join("/tmp", request.param))
    yield request.param
    os.remove(os.path.join("/tmp", request.param))


def create_service_task(sample):
    fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type"]

    return ServiceTask(
        {
            "sid": 1,
            "metadata": {},
            "deep_scan": False,
            "service_name": "Not Important",
            "service_config": {},
            "fileinfo": dict((k, v) for k, v in fileinfo(f"/tmp/{sample}").items() if k in fileinfo_keys),
            "filename": sample,
            "min_classification": "TLP:WHITE",
            "max_files": 501,
            "ttl": 3600,
        }
    )


def drop_ultimate_folder(path):
    path = Path(path)
    return str(path.parents[1].joinpath(path.name))


def generalize_result(result):
    if "response" in result:
        # Ignore the service_started and service_completed timestamps
        if "milestones" in result["response"]:
            if "service_started" in result["response"]["milestones"]:
                result["response"]["milestones"]["service_started"] = None
            if "service_completed" in result["response"]["milestones"]:
                result["response"]["milestones"]["service_completed"] = None

        # Ignore the service_version and service_name
        if "service_version" in result["response"]:
            result["response"]["service_version"] = None
        if "service_name" in result["response"]:
            result["response"]["service_name"] = None

        # Ignore the extracted and supplementary randomized last folder
        if "extracted" in result["response"]:
            for extracted in result["response"]["extracted"]:
                if "path" in extracted:
                    extracted["path"] = drop_ultimate_folder(extracted["path"])
        if "supplementary" in result["response"]:
            for supplementary in result["response"]["supplementary"]:
                if "path" in supplementary:
                    supplementary["path"] = drop_ultimate_folder(supplementary["path"])
                if "is_section_image" in supplementary and "path" in supplementary:
                    if supplementary["is_section_image"]:
                        supplementary["path"] = str(Path(supplementary["path"]).parents[0])


class TestService:
    @classmethod
    def setup_class(cls):
        # Setup where the samples can be found
        cls.locations = [SELF_LOCATION, SAMPLES_LOCATION]

    @staticmethod
    @pytest.mark.parametrize("sample", list_results(SELF_LOCATION), indirect=True)
    def test_service(sample):
        overwrite_results = False  # Used temporarily to mass-correct tests

        cls = Characterize()
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)

        cls.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_path = os.path.join(SELF_LOCATION, "tests", "results", f"{sample}.json")
        with open(correct_path, "r") as f:
            correct_result = json.loads(f.read())

        if overwrite_results:
            import copy

            orig_result = copy.deepcopy(test_result)

        generalize_result(test_result)
        generalize_result(correct_result)
        if overwrite_results:
            if test_result != correct_result:
                with open(correct_path, "w") as f:
                    f.write(json.dumps(orig_result))
        else:
            assert test_result == correct_result
