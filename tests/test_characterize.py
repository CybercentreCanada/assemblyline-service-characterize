import os

import hachoir.core.config as hachoir_config
import pytest
from assemblyline.common.importing import load_module_by_path

from characterize.characterize import get_filepath_from_fileuri

Characterize = load_module_by_path(
    "characterize.characterize.Characterize", os.path.join(os.path.dirname(__file__), "..")
)


class TestCharacterize:
    def test_start(self):
        cls = Characterize()
        cls.start()
        assert hachoir_config.quiet is True

    def test_parse_link(self):
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


@pytest.mark.parametrize(
    # https://en.wikipedia.org/wiki/File_URI_scheme
    "fileuri, filepath",
    [
        ("file://localhost/etc/fstab", "/etc/fstab"),
        ("file:///etc/fstab", "/etc/fstab"),
        ("file:/etc/fstab", "/etc/fstab"),  # KDE type
        ("file://localhost/c:/WINDOWS/clock.avi", "c:/WINDOWS/clock.avi"),
        ("file:///c:/WINDOWS/clock.avi", "c:/WINDOWS/clock.avi"),
        ("file:///c:/WINDOWS/clock.avi", "c:/WINDOWS/clock.avi"),
        # TODO: UNC types, should not have a leading /, but will have it for the moment
        ("file://wikipedia.org/folder/data.xml", "/folder/data.xml"),
        ("file:////wikipedia.org/folder/data.xml", "/folder/data.xml"),
        # Invalid but still used
        ("file://etc/fstab", "/etc/fstab"),
        # Not actually a URI
        ("blob", None),
        # Complex URI
        ("file:\\\\94.156.253.211@80\\Downloads\\run-dwnl-restart.lnk", "\\Downloads\\run-dwnl-restart.lnk"),
    ],
)
def test_get_filepath_from_fileuri(fileuri, filepath):
    print(fileuri, filepath, get_filepath_from_fileuri(fileuri))
    assert get_filepath_from_fileuri(fileuri) == filepath
