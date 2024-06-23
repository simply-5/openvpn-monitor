#!/usr/bin/env python3

# Copyright 2011 VPAC <http://www.vpac.org>
# Copyright 2012-2019 Marcus Furlong <furlongm@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 only.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

import configparser
import os
import subprocess
import sys
from datetime import datetime
from logging import info, warning

import bottle
from bottle import BaseTemplate, HTTPError, request, static_file, view

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openvpn_interface import OpenvpnMgmtInterface


class ConfigLoader:
    def __init__(self, config_path="openvpn-monitor.conf"):
        self.settings = {}
        self.vpns = {}
        config = configparser.ConfigParser()

        if config.read(config_path):
            info(f"Using config file: {config_path}")
        else:
            warning(f"Config file does not exist or is unreadable: {config_path}")
            info("Using default settings => localhost:5555")
            self.vpns["Default VPN"] = {
                "host": "localhost",
                "port": "5555",
                "show_disconnect": False,
            }

        for key, value in config.items():
            if key == config.default_section:
                continue
            elif key == "openvpn-monitor":
                self.parse_global_section(value)
            else:
                self.parse_vpn_section(value)

    def parse_global_section(self, section):
        self.settings = {
            "site": section.get("site", "OpenVPN"),
            "logo": section.get("logo"),
            "datetime_format": section.get("datetime_format", "%d/%m/%Y %H:%M:%S"),
            "geoip_data": section.get("geoip_data", "/usr/share/GeoIP/GeoIPCity.dat"),
            "maps": section.getboolean("maps", True),
        }

    def parse_vpn_section(self, section):
        self.vpns[section.name] = {
            "name": section.get("name", section.name),
            "host": section.get("host", "localhost"),
            "port": section.getint("port", 5555),
            "show_disconnect": section.getboolean("show_disconnect", False),
        }


class FormatUtils:
    @staticmethod
    def naturalsize(quantity, *, decimal_places=1, space="\u00A0", unit="B"):
        for prefix in ["", "Ki", "Mi", "Gi", "Ti", "Pi"]:
            if abs(quantity) < 1024.0 or prefix == "Pi":
                break
            quantity /= 1024.0
        return f"{quantity:.{decimal_places}f}{space}{prefix}{unit}"

    @classmethod
    def data(cls, size):
        return f"""
            <data value="{ size }" title="{ size }">
                { cls.naturalsize(size) }
            </data>"""

    @staticmethod
    def datetime(datetime):
        return f"""
            <time
                datetime="{ datetime.isoformat(timespec='milliseconds') }"
                title="{ datetime.isoformat() }"
            >{ datetime.strftime(config.settings["datetime_format"]) }</time>"""

    @staticmethod
    def timedelta(timedelta):
        return f"""
            <time
                datetime="P{ timedelta.days }DT{ timedelta.seconds }.{ timedelta.microseconds }S"
                title="{ timedelta }"
            >{ str(timedelta)[: -len(".000000")] }</time>"""


application = bottle.default_app()
config = ConfigLoader()
monitor = OpenvpnMgmtInterface(config.vpns, geoip_data=config.settings["geoip_data"])

BaseTemplate.defaults.update(
    {
        "util": FormatUtils(),
        "title": config.settings["site"],
        "logo": config.settings["logo"],
        "now": datetime.now,
    }
)


@application.route("/")
@view("index")
def render_index():
    return {
        "navigation": {
            "VPNs": {vpn: vpn.lower().replace(" ", "_") for vpn in monitor.vpns}
        },
        "vpns": monitor.vpns,
        "show_map": config.settings["maps"],
    }


@application.route("/vpns/<vpn>")
@view("vpn")
def render_vpn(vpn):
    try:
        return {"vpn_name": vpn, "vpn": monitor.vpns[vpn]}
    except KeyError:
        raise HTTPError(404, "VPN not found")


@application.route("/vpns/<vpn>/json")
def return_ansible_hosts(vpn):
    try:
        return monitor.vpns[vpn]["sessions"]
    except KeyError:
        raise HTTPError(404, "VPN not found")


@application.route("/vpns/<vpn>/clients/<client>")
@view("iframe")
def render_client(vpn, client):
    try:
        client = monitor.vpns[vpn]["sessions"][client]
    except KeyError:
        raise HTTPError(404, "Client not found")
    return {"address": f"http://{client['local_ip']}:8080"}


@application.route("/vpns/<vpn>/clients/<client>/ip")
@view("preformatted")
def render_client(vpn, client):
    try:
        client = monitor.vpns[vpn]["sessions"][client]
    except KeyError:
        raise HTTPError(404, "Client not found")
    response = subprocess.run(
        # the actuall command gets overwritten by key options anyhow
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"pi@{client['local_ip']}",
            "ip",
            "addr",
            "show",
            "eth0",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return {"text": response.stdout}


@application.hook("before_request")
def refresh_vpns():
    monitor.refresh()


@application.route("/", method="POST")
def post_slash():
    vpn_name = request.forms.get("vpn_name")
    ip = request.forms.get("ip")
    port = request.forms.get("port")
    client_id = request.forms.get("client_id")
    monitor.kill_client(vpn_name=vpn_name, ip=ip, port=port, client_id=client_id)
    return render_index()


@application.route("/static/<path:path>")
def get_images(path):
    return static_file(path, "./static")


if __name__ == "__main__":
    bottle.debug()
    bottle.run(reloader=True)
