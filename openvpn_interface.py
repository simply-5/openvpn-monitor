import re
import socket
from collections import deque
from datetime import datetime
from ipaddress import ip_address
from logging import debug, info, warning
from pprint import pformat

from semantic_version import Version as semver

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


class OpenvpnMgmtInterface:
    def __init__(self, vpns, *, geoip_data=""):
        self.vpns = vpns

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

        self.refresh()

    def refresh(self):
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
        debug(f"=== begin raw data\n{data}\n=== end raw data")
        return data

    @staticmethod
    def parse_state(data):
        state = {}
        for line in data.splitlines():
            parts = line.split(",")
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

        if sessions:
            pretty_sessions = pformat(sessions)
            debug(f"=== begin sessions\n{pretty_sessions}\n=== end sessions")
        else:
            debug("no sessions")

        return sessions

    @staticmethod
    def parse_version(data):
        for line in data.splitlines():
            if line.startswith("OpenVPN Version: "):
                return line.replace("OpenVPN Version: ", "")

    def kill_client(self, vpn_name, ip, port, client_id):
        vpn = self.vpns[vpn_name]
        self._socket_connect(vpn)
        if vpn["socket_connected"]:
            release = self.send_command("version\n")
            version = semver(self.parse_version(release).split(" ")[1])
            if version.major == 2 and version.minor >= 4 and not port:
                command = "client-kill {0!s}\n".format(client_id)
            else:
                command = "kill {0!s}:{1!s}\n".format(ip, port)
            self.send_command(command)
            self._socket_disconnect()
