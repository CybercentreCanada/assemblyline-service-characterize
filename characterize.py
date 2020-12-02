from __future__ import absolute_import

import json
import re
import subprocess
import hachoir.core.config as hachoir_config

from hachoir.metadata import extractMetadata
from hachoir.parser.guess import createParser

from assemblyline.common.dict_utils import flatten
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

from parse_lnk import decode_lnk


TAG_MAP = {
    'ole2': {
        'author': 'file.ole.summary.author',
        'last_modification': 'file.date.last_modified',
        'subject': 'file.ole.summary.subject',
        'title': 'file.ole.summary.title'
    },
    'LNK': {
        'target_file_dosname': 'file.name.extracted'
    },
    'ZIP': {
        'zip_modify_date': 'file.date.last_modified'
    },
    'EXE': {
        'file_description': 'file.pe.versions.description',
        'time_stamp': 'file.pe.linker.timestamp'
    },
    'DLL': {
        'file_description': 'file.pe.versions.description',
        'time_stamp': 'file.pe.linker.timestamp'
    },
    'DOC': {
        'author': 'file.ole.summary.author',
        'code_page': 'file.ole.summary.codepage',
        'comment': 'file.ole.summary.comment',
        'company': 'file.ole.summary.company',
        'create_date': 'file.date.creation',
        'last_modified_by': 'file.ole.summary.last_saved_by',
        'manager': 'file.ole.summary.manager',
        'modify_date': 'file.date.last_modified',
        'subject': 'file.ole.summary.subject',
        'title': 'file.ole.summary.title'

    },
    None: {
        'image_size': 'file.img.size',
        'megapixels': 'file.img.mega_pixels',
        'create_date': 'file.date.creation',
        'creation_date': 'file.date.creation',
        'modify_date': 'file.date.last_modified',
        'original_file_name': 'file.name.extracted'
    }
}

BAD_LINK_RE = re.compile("http[s]?://|powershell|cscript|wscript|mshta|<script")


def build_key(input_string):
    list_string = list(input_string)
    new_list = []
    previous_upper = False
    for idx, i in enumerate(list_string):
        if i.isupper():
            if idx != 0 and not previous_upper:
                new_list.append("_")

            previous_upper = True
            new_list.append(i.lower())
        elif i in [".", "_"]:
            previous_upper = True
            new_list.append(i)
        else:
            previous_upper = False
            new_list.append(i)

    return "".join(new_list)


def get_type_val(data, src_name):
    key = src_name
    val = data

    if ":" in data:
        key, val = data.split(":", 1)
    elif "=" in data:
        key, val = data.split("=", 1)

    key = build_key(key)
    val = val.strip()
    return key, val


#########################################################
#                  Scan Execution Class                 #
#########################################################
class Characterize(ServiceBase):
    def __init__(self, config=None):
        super(Characterize, self).__init__(config)

    def start(self):
        hachoir_config.quiet = True

    def execute(self, request):
        request.result = Result()

        # 1. Calculate entropy map
        with open(request.file_path, 'rb') as fin:
            (entropy, part_entropies) = calculate_partition_entropy(fin)

        entropy_graph_data = {
            'type': 'colormap',
            'data': {
                'domain': [0, 8],
                'values': part_entropies
            }
        }

        ResultSection(f"File entropy: {round(entropy, 3)}", parent=request.result, body_format=BODY_FORMAT.GRAPH_DATA,
                      body=json.dumps(entropy_graph_data))

        if request.file_type == "meta/shortcut/windows":
            # 2. Parse windows shortcuts
            self.parse_link(request.result, request.file_path)
        else:
            # 3. Get hachoir metadata
            parser = createParser(request.file_path)
            if parser is not None:
                with parser:
                    tags = parser.getParserTags()
                    parser_id = tags.get('id', 'unknown')

                    # Do basic metadata extraction
                    metadata = extractMetadata(parser, 1)

                    if metadata:
                        kv_body = {}
                        tags = []
                        for m in metadata:
                            if m.key == "comment":
                                for v in m.values:
                                    key, val = get_type_val(v.text, "comment")
                                    if not val:
                                        continue

                                    kv_body[key] = val

                                    tag_type = TAG_MAP.get(parser_id, {}).get(key, None) or \
                                        TAG_MAP.get(None, {}).get(key, None)
                                    if tag_type is not None:
                                        tags.append((tag_type, val))
                            elif m.key in ["mime_type"]:
                                pass
                            else:
                                values = [v.text for v in m.values]
                                if len(values) == 1 and values[0]:
                                    kv_body[m.key] = values[0]
                                elif values:
                                    kv_body[m.key] = values

                                for v in values:
                                    tag_type = TAG_MAP.get(parser_id, {}).get(m.key, None) or \
                                        TAG_MAP.get(None, {}).get(m.key, None)
                                    if tag_type is not None:
                                        tags.append((tag_type, v))

                        if kv_body:
                            res = ResultSection(f"Metadata extracted by hachoir-metadata [Parser: {parser_id}]",
                                                body=json.dumps(kv_body), body_format=BODY_FORMAT.KEY_VALUE,
                                                parent=request.result)

                            for t_type, t_val in tags:
                                res.add_tag(t_type, t_val)

        # 4. Get Exiftool Metadata
        exif = subprocess.run(["exiftool", "-j", request.file_path], capture_output=True, check=False)
        if exif.stdout:
            exif_data = json.loads(exif.stdout.decode('utf-8'))
            res_data = exif_data[0]
            if "Error" not in res_data:
                exif_body = {build_key(k): v for k, v in res_data.items()
                             if v and k not in ["SourceFile", "ExifToolVersion", "FileName", "Directory", "FileSize",
                                                "FileModifyDate", "FileAccessDate", "FileInodeChangeDate",
                                                "FilePermissions", "FileType", "FileTypeExtension", "MIMEType"]}
                if exif_body:
                    e_res = ResultSection("Metadata extracted by ExifTool",
                                          body=json.dumps(exif_body), body_format=BODY_FORMAT.KEY_VALUE,
                                          parent=request.result)
                    for k, v in exif_body.items():
                        tag_type = TAG_MAP.get(res_data.get("FileTypeExtension", "UNK").upper(), {}).get(k, None) or \
                                   TAG_MAP.get(None, {}).get(k, None)
                        if tag_type:
                            e_res.add_tag(tag_type, v)

    def parse_link(self, parent_res, path):
        with open(path, "rb") as fh:
            metadata = decode_lnk(fh.read())

        if metadata is None:
            return False

        body_output = {build_key(k): v for k, v in flatten(metadata).items() if v}
        res = ResultSection("Metadata extracted by parse_lnk", body_format=BODY_FORMAT.KEY_VALUE,
                            body=json.dumps(body_output), parent=parent_res)

        bp = metadata.get("BasePath", "").strip()
        rp = metadata.get("RELATIVE_PATH", "").strip()
        nn = metadata.get("NetName", "").strip()
        cla = metadata.get("COMMAND_LINE_ARGUMENTS", "").strip()
        s = BAD_LINK_RE.search(cla.lower())
        if s:
            res.set_heuristic(1)
        res.add_tag(tag_type="file.name.extracted", value=(bp or rp or nn).rsplit("\\")[-1])
        res.add_tag(tag_type="dynamic.process.command_line", value=f"{(rp or bp or nn)} {cla}".strip())

        for k, v in body_output.items():
            tag_type = TAG_MAP.get("LNK", {}).get(k, None) or \
                       TAG_MAP.get(None, {}).get(k, None)
            if tag_type:
                res.add_tag(tag_type, v)

        return True
