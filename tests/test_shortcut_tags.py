import json
from unittest.mock import Mock

import pytest
from assemblyline_v4_service.common.result import Result

from characterize.characterize import Characterize

SID_FORMAT_ID = "46588AE2-4CBC-4338-BBFC-139326986DCE"
SID = "S-1-5-21-100-200-300-1001"


@pytest.fixture
def run_shortcut(tmp_path, monkeypatch):
    def run(link_info=None, property_stores=None):
        features = {
            "header": {"creation_time": None, "modified_time": None, "accessed_time": None},
            "link_info": link_info if link_info is not None else {},
            "data": {"relative_path": "example.txt"},
            "extra": {},
        }
        if property_stores is not None:
            features["extra"]["METADATA_PROPERTIES_BLOCK"] = {"property_store": property_stores}
        parser = Mock(extras=[])
        parser.get_json.return_value = features
        parse = Mock(return_value=parser)
        monkeypatch.setattr("characterize.characterize.LnkParse3.lnk_file", parse)

        file_path = tmp_path / "example.lnk"
        file_path.write_bytes(b"")
        request = Mock(file_path=str(file_path), result=Result())
        request.task.depth = 0
        service = Characterize()
        service._working_directory = str(tmp_path)
        service.handle_windows_shortcut(request)

        parse.assert_called_once()
        parser.get_json.assert_called_once_with(get_all=True)
        request.add_extracted.assert_not_called()
        request.add_supplementary.assert_called_once_with(
            str(tmp_path / "features.json"), "features.json", "Features extracted from the LNK file"
        )
        assert json.loads((tmp_path / "features.json").read_text()) == features
        tags = request.result.sections[0].tags
        assert tags["file.shortcut.command_line"] == ["example.txt"]
        return tags

    return run


def sid_store(value=SID, format_id=SID_FORMAT_ID, property_id=4):
    return {
        "format_id": format_id,
        "serialized_property_values": [{"id": property_id, "value": value, "value_type": "VT_LPWSTR"}],
    }


def test_shortcut_identity_tags(run_shortcut):
    tags = run_shortcut(
        {"location_info": {"drive_serial_number": "0x5a8c5e7d"}},
        [sid_store()],
    )
    assert tags["file.shortcut.sid"] == [SID]
    assert tags["file.shortcut.drive_serial"] == ["5A8C5E7D"]


@pytest.mark.parametrize("link_info", [{}, {"location_info": {}}])
@pytest.mark.parametrize("property_stores", [None, [], [{}]])
def test_missing_shortcut_identity_tags(run_shortcut, link_info, property_stores):
    tags = run_shortcut(link_info, property_stores)
    assert "file.shortcut.sid" not in tags
    assert "file.shortcut.drive_serial" not in tags


@pytest.mark.parametrize(
    "serial, expected",
    [("0x0", "00000000"), ("0x123", "00000123"), ("0xabcdef", "00ABCDEF"), ("0xffffffff", "FFFFFFFF")],
)
def test_drive_serial_normalization(run_shortcut, serial, expected):
    tags = run_shortcut({"location_info": {"drive_serial_number": serial}})
    assert tags["file.shortcut.drive_serial"] == [expected]
    assert "file.shortcut.sid" not in tags


@pytest.mark.parametrize(
    "store",
    [
        sid_store(format_id="00000000-0000-0000-0000-000000000000"),
        sid_store(property_id=5),
        sid_store(value=None),
        sid_store(value=123),
        sid_store(value=""),
        sid_store(value="not a SID"),
        sid_store(value="prefix S-1-5-21-100-200-300-1001"),
        sid_store(value="S-1-5-21-100-200-300-1001 suffix"),
    ],
)
def test_unrelated_or_invalid_sid_is_not_tagged(run_shortcut, store):
    assert "file.shortcut.sid" not in run_shortcut(property_stores=[store])


def test_multiple_sid_properties_and_stores(run_shortcut):
    second_sid = "S-1-5-21-400-500-600-1002"
    store = sid_store()
    store["serialized_property_values"].extend([{"id": 5, "value": "unrelated"}, {"id": 4, "value": second_sid}])
    tags = run_shortcut(property_stores=[store, sid_store(format_id=SID_FORMAT_ID.lower())])
    assert tags["file.shortcut.sid"] == [SID, second_sid]
    assert "file.shortcut.drive_serial" not in tags
