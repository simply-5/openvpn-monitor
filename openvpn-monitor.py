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
from ipaddress import IPv4Address, IPv6Address
import json
import os
import subprocess
import sys
from datetime import datetime
from logging import info, warning

import bottle
from bottle import HTTPError, request, static_file

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openvpn_interface import OpenvpnMgmtInterface
from openvpn_views import (
    render_iframe,
    render_index as render_index_page,
    render_preformatted,
    render_vpn as render_vpn_page,
)


class ConfigLoader:
    def __init__(self, config_path="openvpn-monitor.conf"):
        self.settings = {}
        self.vpns = {}
        # No value here is a template for another one,
        # and datetime_format is full of the % that interpolation claims,
        # so it would only ever be in the way
        config = configparser.ConfigParser(interpolation=None)

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
            # Passed to the ssh of the client detail route.
            # ssh expands ~ against the home in the passwd database and
            # ignores $HOME, so unset is right wherever that lookup lands
            # on the credentials. A systemd DynamicUser= account has no
            # home of its own, its passwd entry reads /, and nothing can
            # point ssh elsewhere - which is what these are for.
            "ssh_identity_file": section.get("ssh_identity_file"),
            "ssh_known_hosts_file": section.get("ssh_known_hosts_file"),
        }

    def parse_vpn_section(self, section):
        self.vpns[section.name] = {
            "name": section.get("name", section.name),
            "host": section.get("host", "localhost"),
            "port": section.getint("port", 5555),
            "show_disconnect": section.getboolean("show_disconnect", False),
        }


application = bottle.default_app()
config = ConfigLoader()
monitor = OpenvpnMgmtInterface(config.vpns, geoip_data=config.settings["geoip_data"])

@application.route("/")
def render_index():
    return render_index_page(
        config.settings,
        monitor.vpns,
        show_map=config.settings["maps"],
        now=datetime.now(),
    )


@application.route("/vpns/<vpn>")
def render_vpn(vpn):
    try:
        vpn_data = monitor.vpns[vpn]
    except KeyError:
        raise HTTPError(404, "VPN not found")
    return render_vpn_page(config.settings, vpn, vpn_data, now=datetime.now())


class ExtendedJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, (IPv4Address, IPv6Address)):
            return str(obj)
        # Let the base class default method raise the TypeError
        return super().default(obj)


@application.route("/vpns/<vpn>/json")
def return_ansible_hosts(vpn):
    try:
        # We cannot tell bottle which encoder to use
        # so we convert everything ourselves first
        # and then let bottle do the rest (set the content-type header etc.)
        return json.loads(
            json.dumps(monitor.vpns[vpn]["sessions"], cls=ExtendedJSONEncoder)
        )
    except KeyError:
        raise HTTPError(404, "VPN not found")


@application.route("/vpns/<vpn>/clients/<client>")
def render_client(vpn, client):
    try:
        client = monitor.vpns[vpn]["sessions"][client]
    except KeyError:
        raise HTTPError(404, "Client not found")
    return render_iframe(
        config.settings, f"http://{client['local_ip']}:8080", now=datetime.now()
    )


@application.route("/vpns/<vpn>/clients/<client>/ip")
def render_client(vpn, client):
    try:
        client = monitor.vpns[vpn]["sessions"][client]
    except KeyError:
        raise HTTPError(404, "Client not found")
    command = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if config.settings["ssh_identity_file"]:
        command += ["-i", config.settings["ssh_identity_file"]]
        # Without this the named key is only one candidate among the
        # agent's and the default names, and a server that refuses too
        # many of those closes the connection before reaching it
        command += ["-o", "IdentitiesOnly=yes"]
    if config.settings["ssh_known_hosts_file"]:
        command += [
            "-o",
            f"UserKnownHostsFile={config.settings['ssh_known_hosts_file']}",
        ]
    response = subprocess.run(
        # the actuall command gets overwritten by key options anyhow
        command + [f"pi@{client['local_ip']}", "ip", "addr", "show", "eth0"],
        check=True,
        capture_output=True,
        text=True,
    )
    return render_preformatted(config.settings, response.stdout, now=datetime.now())


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
