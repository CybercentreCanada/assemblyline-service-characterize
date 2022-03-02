import hachoir.core.config as hachoir_config

from characterize import Characterize


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
