import hachoir.core.config as hachoir_config
import os

from assemblyline.common.importing import load_module_by_path

Characterize = load_module_by_path("characterize.Characterize", os.path.join(os.path.dirname(__file__), ".."))


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
