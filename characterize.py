import json

from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT


class Characterize(ServiceBase):
    """ Basic File Characterization.

    Currently characterize only generates file partition entropy data.
    """
    def __init__(self, config=None):
        super(Characterize, self).__init__(config)

    def execute(self, request):
        path = request.download_file()
        with open(path, 'rb') as fin:
            (entropy, part_entropies) = calculate_partition_entropy(fin)

        entropy_graph_data = {
            'type': 'colormap',
            'data': {
                'domain': [0, 8],
                'values': part_entropies
            }
        }
        section = ResultSection(
            title_text=f"File entropy: {round(entropy, 3)}",
            body_format=BODY_FORMAT.GRAPH_DATA,
            body=json.dumps(entropy_graph_data)
        )
        result = Result()
        result.add_section(section)
        request.result = result
