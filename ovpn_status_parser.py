import csv
import json

import datetime as dt
from itertools import chain, dropwhile, takewhile
from pathlib import Path
from typing import NamedTuple, Union


class OpenVPNStatus(NamedTuple):
    title: str
    time: dt.datetime
    client_list: list[dict[str, Union[str, int, dt.datetime]]]
    routing_table: list[dict[str, Union[str, int, dt.datetime]]]
    global_stats: dict[str, str]


class JSONDatetimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, dt.datetime):
            return obj.isoformat()
        # Let the base class default method raise the TypeError
        return super().default(obj)


def extract_section(lines, section_name):
    leaders_removed = dropwhile(
        lambda x: not x.startswith(f"HEADER,{section_name},"), lines
    )
    header = next(leaders_removed)
    followers_removed = takewhile(
        lambda x: x.startswith(section_name + ","), leaders_removed
    )
    return chain(
        [header.removeprefix(f"HEADER,{section_name},")],
        (line.removeprefix(section_name + ",") for line in followers_removed),
    )


def parse_openvpn_status_file(content: str):
    lines = content.splitlines()

    [title_line, time_line, *body, _end_line] = lines

    assert _end_line == "END"

    title = title_line.removeprefix("TITLE,")
    time = dt.datetime.fromtimestamp(
        int(time_line.removeprefix("TIME,").split(",")[-1])
    )
    client_list = []
    routing_table = []
    global_stats = {}

    for record in csv.DictReader(extract_section(body, "CLIENT_LIST"), dialect="unix"):
        # Convert specific fields to appropriate types
        record["Bytes Received"] = int(record["Bytes Received"])
        record["Bytes Sent"] = int(record["Bytes Sent"])
        record["Client ID"] = int(record["Client ID"])
        record["Peer ID"] = int(record["Peer ID"])
        record["Connected Since"] = dt.datetime.strptime(
            record["Connected Since"], "%Y-%m-%d %H:%M:%S"
        )
        record["Connected Since (time_t)"] = dt.datetime.fromtimestamp(
            int(record["Connected Since (time_t)"])
        )
        assert record["Connected Since"] == record["Connected Since (time_t)"]
        del record["Connected Since (time_t)"]
        client_list.append(record)

    for record in csv.DictReader(
        extract_section(body, "ROUTING_TABLE"), dialect="unix"
    ):
        # Convert specific fields to appropriate types
        record["Last Ref"] = dt.datetime.strptime(
            record["Last Ref"], "%Y-%m-%d %H:%M:%S"
        )
        record["Last Ref (time_t)"] = dt.datetime.fromtimestamp(
            int(record["Last Ref (time_t)"])
        )
        assert record["Last Ref"] == record["Last Ref (time_t)"]
        del record["Last Ref (time_t)"]

        routing_table.append(record)

    for _line_prefix, global_stat_name, stat_value in csv.reader(
        (line for line in body if line.startswith("GLOBAL_STATS,")), dialect="unix"
    ):
        global_stats[global_stat_name] = stat_value

    return OpenVPNStatus(title, time, client_list, routing_table, global_stats)


# Example usage
# file_path = "status.log"
# content = Path(file_path).read_text()
# parsed_data = parse_openvpn_status_file(content)
# json_data = json.dumps(parsed_data, cls=JSONDatetimeEncoder, indent=4)
