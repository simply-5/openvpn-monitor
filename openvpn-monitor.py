#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import argparse
import configparser
import os
import re
import socket
import string
import sys
from collections import deque
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from pprint import pformat

import bottle
from bottle import Bottle, request, response, static_file, template, view
from semantic_version import Version as semver


def naturalsize(size, *, decimal_places=1, space="\u00A0", suffix="B"):
    for prefix in ["", "Ki", "Mi", "Gi", "Ti", "Pi"]:
        if abs(size) < 1024.0 or prefix == "Pi":
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f}{space}{prefix}{suffix}"


try:
    import GeoIP as geoip1

    geoip1_available = True
except ImportError:
    geoip1_available = False

try:
    from geoip2 import database
    from geoip2.errors import AddressNotFoundError

    geoip2_available = True
except ImportError:
    geoip2_available = False


def info(*objs):
    print("INFO:", *objs, file=sys.stderr)


def warning(*objs):
    print("WARNING:", *objs, file=sys.stderr)


def debug(*objs):
    print("DEBUG:\n", *objs, file=sys.stderr)


class ConfigLoader(object):
    def __init__(self, config_file):
        self.settings = {
            "site": "OpenVPN",
            "maps": "True",
            "geoip_data": "/usr/share/GeoIP/GeoIPCity.dat",
            "datetime_format": "%d/%m/%Y %H:%M:%S",
        }
        self.vpns = {}
        config = configparser.ConfigParser()
        contents = config.read(config_file)

        if not contents and config_file == "./openvpn-monitor.conf":
            warning(f"Config file does not exist or is unreadable: {config_file}")
            if sys.prefix == "/usr":
                conf_path = "/etc/"
            else:
                conf_path = sys.prefix + "/etc/"
            config_file = conf_path + "openvpn-monitor.conf"
            contents = config.read(config_file)

        if contents:
            info(f"Using config file: {config_file}")
        else:
            warning(f"Config file does not exist or is unreadable: {config_file}")
            info("Using default settings => localhost:5555")
            self.vpns["Default VPN"] = {
                "name": "default",
                "host": "localhost",
                "port": "5555",
                "show_disconnect": False,
            }

        for section in config.sections():
            if section == "openvpn-monitor":
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)

    def parse_global_section(self, config):
        global_vars = [
            "site",
            "logo",
            "latitude",
            "longitude",
            "maps",
            "geoip_data",
            "datetime_format",
        ]
        for var in global_vars:
            try:
                self.settings[var] = config.get("openvpn-monitor", var)
            except configparser.NoOptionError:
                pass
        if args.debug:
            debug(f"=== begin section\n{self.settings}\n=== end section")

    def parse_vpn_section(self, config, section):
        self.vpns[section] = {}
        vpn = self.vpns[section]
        options = config.options(section)
        for option in options:
            try:
                vpn[option] = config.get(section, option)
                if vpn[option] == -1:
                    warning(f"CONFIG: skipping {option}")
            except configparser.Error as e:
                warning(f"CONFIG: {e} on option {option}: ")
                vpn[option] = None
        if "show_disconnect" in vpn and vpn["show_disconnect"] == "True":
            vpn["show_disconnect"] = True
        else:
            vpn["show_disconnect"] = False
        if args.debug:
            debug(f"=== begin section\n{vpn}\n=== end section")


class OpenvpnMgmtInterface(object):
    def __init__(self, cfg, **kwargs):
        self.vpns = cfg.vpns

        if "vpn_id" in kwargs:
            vpn = self.vpns[kwargs["vpn_id"]]
            self._socket_connect(vpn)
            if vpn["socket_connected"]:
                release = self.send_command("version\n")
                version = semver(self.parse_version(release).split(" ")[1])
                if version.major == 2 and version.minor >= 4 and "port" not in kwargs:
                    command = "client-kill {0!s}\n".format(kwargs["client_id"])
                else:
                    command = "kill {0!s}:{1!s}\n".format(kwargs["ip"], kwargs["port"])
                self.send_command(command)
                self._socket_disconnect()

        geoip_data = cfg.settings["geoip_data"]
        self.geoip_version = None
        self.gi = None
        try:
            if geoip_data.endswith(".mmdb") and geoip2_available:
                self.gi = database.Reader(geoip_data)
                self.geoip_version = 2
            elif geoip_data.endswith(".dat") and geoip1_available:
                self.gi = geoip1.open(geoip_data, geoip1.GEOIP_STANDARD)
                self.geoip_version = 1
            else:
                warning("No compatible geoip1 or geoip2 data/libraries found.")
        except IOError:
            warning("No compatible geoip1 or geoip2 data/libraries found.")

        for key, vpn in list(self.vpns.items()):
            self._socket_connect(vpn)
            if vpn["socket_connected"]:
                self.collect_data(vpn)
                self._socket_disconnect()

    def collect_data(self, vpn):
        ver = self.send_command("version\n")
        vpn["release"] = self.parse_version(ver)
        vpn["version"] = semver(vpn["release"].split(" ")[1])
        state = self.send_command("state\n")
        vpn["state"] = self.parse_state(state)
        stats = self.send_command("load-stats\n")
        vpn["stats"] = self.parse_stats(stats)
        status = self.send_command("status 3\n")
        vpn["sessions"] = self.parse_status(status, vpn["version"])

    def _socket_send(self, command):
        self.s.send(command.encode())

    def _socket_recv(self, length):
        return self.s.recv(length).decode()

    def _socket_connect(self, vpn):
        timeout = 3
        self.s = None
        try:
            if "socket" in vpn:
                self.s = socket.socket(socket.AF_UNIX)
                self.s.connect(vpn["socket"])
            else:
                address = (vpn["host"], int(vpn["port"]))
                self.s = socket.create_connection(address, timeout)
            vpn["socket_connected"] = True
        except socket.timeout as e:
            vpn["error"] = "{0!s}".format(e)
            warning("socket timeout: {0!s}".format(e))
            vpn["socket_connected"] = False
            if self.s:
                self.s.close()
        except socket.error as e:
            vpn["error"] = "{0!s}".format(e.strerror)
            warning("socket error: {0!s}".format(e))
            vpn["socket_connected"] = False
        except Exception as e:
            vpn["error"] = "{0!s}".format(e)
            warning("unexpected error: {0!s}".format(e))
            vpn["socket_connected"] = False

    def _socket_disconnect(self):
        self._socket_send("quit\n")
        self.s.close()

    def send_command(self, command):
        info(f"Sending command: {command}")
        self._socket_send(command)
        data = ""
        if command.startswith("kill") or command.startswith("client-kill"):
            return
        while 1:
            socket_data = self._socket_recv(1024)
            socket_data = re.sub(">INFO(.)*\r\n", "", socket_data)
            data += socket_data
            if command == "load-stats\n" and data != "":
                break
            elif data.endswith("\nEND\r\n"):
                break
        if args.debug:
            debug(f"=== begin raw data\n{data}\n=== end raw data")
        return data

    @staticmethod
    def parse_state(data):
        state = {}
        for line in data.splitlines():
            parts = line.split(",")
            if args.debug:
                debug(f"=== begin split line\n{parts}\n=== end split line")
            if (
                parts[0].startswith(">INFO")
                or parts[0].startswith("END")
                or parts[0].startswith(">CLIENT")
            ):
                continue
            else:
                state["up_since"] = datetime.fromtimestamp(int(parts[0]))
                state["connected"] = parts[1]
                state["success"] = parts[2]
                if parts[3]:
                    state["local_ip"] = ip_address(parts[3])
                else:
                    state["local_ip"] = ""
                if parts[4]:
                    state["remote_ip"] = ip_address(parts[4])
                    state["mode"] = "Client"
                else:
                    state["remote_ip"] = ""
                    state["mode"] = "Server"
        return state

    @staticmethod
    def parse_stats(data):
        stats = {}
        line = re.sub("SUCCESS: ", "", data)
        parts = line.split(",")
        if args.debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
        stats["nclients"] = int(re.sub("nclients=", "", parts[0]))
        stats["bytesin"] = int(re.sub("bytesin=", "", parts[1]))
        stats["bytesout"] = int(re.sub("bytesout=", "", parts[2]).replace("\r\n", ""))
        return stats

    def parse_status(self, data, version):
        gi = self.gi
        geoip_version = self.geoip_version
        client_section = False
        routes_section = False
        sessions = {}
        client_session = {}

        for line in data.splitlines():
            parts = deque(line.split("\t"))
            if args.debug:
                debug(f"=== begin split line\n{parts}\n=== end split line")

            if parts[0].startswith("END"):
                break
            if (
                parts[0].startswith("TITLE")
                or parts[0].startswith("GLOBAL")
                or parts[0].startswith("TIME")
            ):
                continue
            if parts[0] == "HEADER":
                if parts[1] == "CLIENT_LIST":
                    client_section = True
                    routes_section = False
                if parts[1] == "ROUTING_TABLE":
                    client_section = False
                    routes_section = True
                continue

            if (
                parts[0].startswith("TUN")
                or parts[0].startswith("TCP")
                or parts[0].startswith("Auth")
            ):
                parts = parts[0].split(",")
            if parts[0] == "TUN/TAP read bytes":
                client_session["tuntap_read"] = int(parts[1])
                continue
            if parts[0] == "TUN/TAP write bytes":
                client_session["tuntap_write"] = int(parts[1])
                continue
            if parts[0] == "TCP/UDP read bytes":
                client_session["tcpudp_read"] = int(parts[1])
                continue
            if parts[0] == "TCP/UDP write bytes":
                client_session["tcpudp_write"] = int(parts[1])
                continue
            if parts[0] == "Auth read bytes":
                client_session["auth_read"] = int(parts[1])
                sessions["Client"] = client_session
                continue

            if client_section:
                session = {}
                parts.popleft()
                common_name = parts.popleft()
                remote_str = parts.popleft()
                if remote_str.count(":") == 1:
                    remote, port = remote_str.split(":")
                elif "(" in remote_str:
                    remote, port = remote_str.split("(")
                    port = port[:-1]
                else:
                    remote = remote_str
                    port = None
                remote_ip = ip_address(remote)
                session["remote_ip"] = remote_ip
                if port:
                    session["port"] = int(port)
                else:
                    session["port"] = ""
                if session["remote_ip"].is_private:
                    session["location"] = "RFC1918"
                else:
                    try:
                        if geoip_version == 1:
                            gir = gi.record_by_addr(str(session["remote_ip"]))
                            session["location"] = gir["country_code"]
                            session["region"] = gir["region"]
                            session["city"] = gir["city"]
                            session["country"] = gir["country_name"]
                            session["longitude"] = gir["longitude"]
                            session["latitude"] = gir["latitude"]
                        elif geoip_version == 2:
                            gir = gi.city(str(session["remote_ip"]))
                            session["location"] = gir.country.iso_code
                            session["region"] = gir.subdivisions.most_specific.iso_code
                            session["city"] = gir.city.name
                            session["country"] = gir.country.name
                            session["longitude"] = gir.location.longitude
                            session["latitude"] = gir.location.latitude
                    except (AddressNotFoundError, TypeError, SystemError):
                        pass
                local_ipv4 = parts.popleft()
                if local_ipv4:
                    session["local_ip"] = ip_address(local_ipv4)
                else:
                    session["local_ip"] = ""
                if version.major >= 2 and version.minor >= 4:
                    local_ipv6 = parts.popleft()
                    if local_ipv6:
                        session["local_ip"] = ip_address(local_ipv6)
                session["bytes_recv"] = int(parts.popleft())
                session["bytes_sent"] = int(parts.popleft())
                parts.popleft()
                session["connected_since"] = datetime.fromtimestamp(
                    int(parts.popleft())
                )
                username = parts.popleft()
                if username != "UNDEF":
                    session["username"] = username
                else:
                    session["username"] = common_name
                if version.major == 2 and version.minor >= 4:
                    session["client_id"] = parts.popleft()
                    session["peer_id"] = parts.popleft()
                sessions[str(session["local_ip"])] = session

            if routes_section:
                local_ip = parts[1]
                remote_ip = parts[3]
                last_seen = datetime.fromtimestamp(int(parts[5]))
                if local_ip in sessions:
                    sessions[local_ip]["last_seen"] = last_seen
                elif self.is_mac_address(local_ip):
                    matching_local_ips = [
                        sessions[s]["local_ip"]
                        for s in sessions
                        if remote_ip
                        == self.get_remote_address(
                            sessions[s]["remote_ip"], sessions[s]["port"]
                        )
                    ]
                    if len(matching_local_ips) == 1:
                        local_ip = "{0!s}".format(matching_local_ips[0])
                        if "last_seen" in sessions[local_ip]:
                            prev_last_seen = sessions[local_ip]["last_seen"]
                            if prev_last_seen < last_seen:
                                sessions[local_ip]["last_seen"] = last_seen
                        else:
                            sessions[local_ip]["last_seen"] = last_seen

        if args.debug:
            if sessions:
                pretty_sessions = pformat(sessions)
                debug(f"=== begin sessions\n{pretty_sessions}\n=== end sessions")
            else:
                debug("no sessions")

        return sessions

    @staticmethod
    def parse_version(data):
        for line in data.splitlines():
            if line.startswith("OpenVPN"):
                return line.replace("OpenVPN Version: ", "")

    @staticmethod
    def is_mac_address(s):
        return (
            len(s) == 17
            and len(s.split(":")) == 6
            and all(c in string.hexdigits for c in s.replace(":", ""))
        )

    @staticmethod
    def get_remote_address(ip, port):
        if port:
            return "{0!s}:{1!s}".format(ip, port)
        else:
            return "{0!s}".format(ip)


class OpenvpnHtmlPrinter(object):
    def __init__(self, cfg, monitor):
        global wsgi_output
        self.init_vars(cfg.settings, monitor)
        wsgi_output += self.print_html_header()
        for key, vpn in self.vpns:
            if vpn["socket_connected"]:
                wsgi_output += self.print_vpn(key, vpn)
            else:
                wsgi_output += self.print_unavailable_vpn(vpn)
        if self.maps:
            wsgi_output += self.print_maps_html()
        wsgi_output += self.print_html_footer()

    def init_vars(self, settings, monitor):

        self.vpns = list(monitor.vpns.items())

        self.site = "OpenVPN"
        if "site" in settings:
            self.site = settings["site"]

        self.logo = None
        if "logo" in settings:
            self.logo = settings["logo"]

        self.maps = False
        if "maps" in settings and settings["maps"] == "True":
            self.maps = True

        self.latitude = 40.72
        self.longitude = -74
        if "latitude" in settings:
            self.latitude = settings["latitude"]
        if "longitude" in settings:
            self.longitude = settings["longitude"]

        self.datetime_format = settings["datetime_format"]

    @view("html_header")
    def print_html_header(self):
        return {
            "logo": self.logo,
            "site": self.site,
            "vpns": self.vpns,
            "maps": self.maps,
        }

    @view("vpn_unavailable_view")
    def print_unavailable_vpn(self, vpn):
        return {"vpn": vpn}

    @view("vpn_view")
    def print_vpn(self, vpn_id, vpn):
        return {
            "naturalsize": naturalsize,
            "vpn": vpn,
            "datetime_format": self.datetime_format,
            "now": datetime.now(),
            "vpn_id": vpn_id,
        }

    @view("map_view")
    def print_maps_html(self):
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "vpns": self.vpns,
        }

    @view("html_footer")
    def print_html_footer(self):
        return {"now": datetime.now(), "format": self.datetime_format}


def main(**kwargs):
    cfg = ConfigLoader(args.config)
    monitor = OpenvpnMgmtInterface(cfg, **kwargs)
    OpenvpnHtmlPrinter(cfg, monitor)
    if args.debug:
        pretty_vpns = pformat(dict(monitor.vpns))
        debug(f"=== begin vpns\n{pretty_vpns}\n=== end vpns")


def get_args():
    parser = argparse.ArgumentParser(
        description="Display a html page with openvpn status and connections"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        required=False,
        default=False,
        help="Run in debug mode",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=False,
        default="./openvpn-monitor.conf",
        help="Path to config file openvpn-monitor.conf",
    )
    return parser.parse_args()


def monitor_wsgi():

    owd = str(Path.cwd())
    if owd.endswith("site-packages") and sys.prefix != "/usr":
        # virtualenv
        image_dir = owd + "/../../../share/openvpn-monitor/"
    else:
        image_dir = ""

    bottle.debug()
    app = Bottle()

    @app.route("/", method="GET")
    def render(**kwargs):
        global wsgi_output
        wsgi_output = ""
        main(**kwargs)
        response.content_type = "text/html;"
        return wsgi_output

    @app.hook("before_request")
    def strip_slash():
        request.environ["PATH_INFO"] = request.environ.get("PATH_INFO", "/").rstrip("/")
        if args.debug:
            debug(pformat(request.environ))

    @app.route("/", method="POST")
    def post_slash():
        vpn_id = request.forms.get("vpn_id")
        ip = request.forms.get("ip")
        port = request.forms.get("port")
        client_id = request.forms.get("client_id")
        return render(vpn_id=vpn_id, ip=ip, port=port, client_id=client_id)

    @app.route("/<filename:re:.*\.(jpg|png)>", method="GET")
    def get_images(filename):
        return static_file(filename, image_dir)

    return app


if False and __name__ == "__main__":
    args = get_args()
    wsgi = False
    wsgi_output = ""
    main()
    # bottle run ...
else:
    os.chdir(os.path.dirname(__file__))

    class args(object):
        debug = False
        config = "./openvpn-monitor.conf"

    sys.path.append(__file__)
    wsgi = True
    wsgi_output = ""
    application = monitor_wsgi()
