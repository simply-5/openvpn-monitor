"""Pages of the monitor, written with hyperscribe."""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta
from io import StringIO
from typing import Any

from hyperscribe import DocWriter, escape

BOOTSTRAP_CSS = {
    "rel": "stylesheet",
    "href": "https://cdn.jsdelivr.net/npm/bootstrap@6.0.0-alpha.1/dist/css/bootstrap.min.css",
    "integrity": "sha384-B/GM4XqrwHnWXNOWMbloTmrYXZg10cakYGmpfsR/bbzQ6JAJI4ihuyADKLnBgrCe",
    "crossorigin": "anonymous",
}
# Bootstrap 6 ships only ES modules.
# The bundle includes Floating UI, which the menus need.
BOOTSTRAP_JS = {
    "type": "module",
    "src": "https://cdn.jsdelivr.net/npm/bootstrap@6.0.0-alpha.1/dist/js/bootstrap.bundle.min.js",
    "integrity": "sha384-1a/pXj49ZQ1aHEmrJ+gMw1otqoVsYwlEnlD8mIfY2TV03r20Y0CN7uqx1tQogjPL",
    "crossorigin": "anonymous",
}
LEAFLET_CSS = {
    "rel": "stylesheet",
    "href": "https://unpkg.com/leaflet@1.6.0/dist/leaflet.css",
    "integrity": "sha512-xwE/Az9zrjBIphAcBb3F6JVqxf46+CDLwfLMHloNu6KEQCAWi6HcDUbeOfBIptF7tcCzusKFjFw2yuvEpDL9wQ==",
    "crossorigin": "anonymous",
}
LEAFLET_JS = {
    "src": "https://unpkg.com/leaflet@1.6.0/dist/leaflet.js",
    "integrity": "sha512-gZwIG9x3wUXg2hdXF6+rVkLF/0Vi9U8D2Ntg4Ga5I5BZpVkVxlJWbSQtXPSiUTtC0TjtGOmxa1AJPuV0CPthew==",
    "crossorigin": "anonymous",
}

# hyperscribe leaves scripts alone, and escaping would break the braces
# and quotes in them, so this goes in raw.
MAP_SCRIPT = """\
const map = L.map("map_canvas");
const centre = L.latLng(0, 0);
map.setView(centre, 8);
const layer = new L.TileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {});
map.addLayer(layer);
const bounds = L.latLngBounds(centre);
"""

Settings = Mapping[str, Any]


def naturalsize(quantity, *, decimal_places=1, space="\u00a0", unit="B"):
    for prefix in ["", "Ki", "Mi", "Gi", "Ti", "Pi"]:
        if abs(quantity) < 1024.0 or prefix == "Pi":
            break
        quantity /= 1024.0
    return f"{quantity:.{decimal_places}f}{space}{prefix}{unit}"


def _data(doc: DocWriter, size: int) -> None:
    t = doc.tags
    t.data(escape(naturalsize(size)), value=size, title=size)


def _datetime(doc: DocWriter, settings: Settings, value: datetime) -> None:
    t = doc.tags
    t.time(
        escape(value.strftime(settings["datetime_format"])),
        datetime=value.isoformat(timespec="milliseconds"),
        title=value.isoformat(),
    )


def _timedelta(doc: DocWriter, value: timedelta) -> None:
    t = doc.tags
    t.time(
        escape(str(value).split(".")[0]),
        datetime=f"P{value.days}DT{value.seconds}.{value.microseconds}S",
        title=value,
    )


def _anchor(name: str) -> str:
    return name.lower().replace(" ", "_")


@contextmanager
def _page(
    doc: DocWriter,
    settings: Settings,
    *,
    navigation: Mapping[str, Any] | None = None,
    fullpage: bool = False,
    now: datetime,
) -> Iterator[None]:
    t = doc.tags
    v = doc.voids
    title = settings["site"]
    logo = settings["logo"]

    doc("<!DOCTYPE html>")
    with t.html(lang="en", class_="h-100"):
        with t.head:
            v.meta(charset="UTF-8")
            t.title(escape(f"{title} - Status Monitor"))
            v.meta(
                name="viewport",
                content="width=device-width, initial-scale=1.0",
            )
            v.meta(**{"http-equiv": "refresh"}, content="300")
            v.meta(
                name="description",
                content="Monitor VPN servers and clients",
            )
            v.link(**BOOTSTRAP_CSS)
            t.script("", **BOOTSTRAP_JS)
            t.script("", src="/static/main.js", defer="")
            v.link(rel="stylesheet", href="/static/master.css")

        with t.body(class_="d-flex flex-column h-100"):
            _header(doc, title, logo, navigation or {})
            with t.main(
                id="main",
                class_="flex-grow-1" + ("" if fullpage else " xl:container"),
            ):
                yield
            with t.footer(
                id="footer", class_="navbar bg-3", data={"bs-theme": "dark"}
            ):
                with t.div(class_="container"):
                    with t.div(class_="navbar-text"):
                        doc("Page automatically reloads every 5 minutes.")
                        doc("Last update:")
                        _datetime(doc, settings, now)


def _header(
    doc: DocWriter, title: str, logo: str | None, navigation: Mapping[str, Any]
) -> None:
    t = doc.tags
    v = doc.voids
    with t.header(
        id="header",
        class_="sticky-top navbar sm:navbar-expand bg-3",
        data={"bs-theme": "dark"},
    ):
        with t.nav(class_="container"):
            with doc.inline(), t.a(class_="navbar-brand", href="/"):
                if logo:
                    v.img(
                        src=f"/static/images/{logo}",
                        alt="Logo",
                        class_="rounded",
                        style="height: 1.5em;",
                    )
                    doc(" ")
                doc(escape(title))
                doc(" - Status Monitor")
            with t.button(
                class_="btn-icon navbar-toggler",
                type="button",
                data={"bs-toggle": "drawer", "bs-target": "#navbar"},
                aria={
                    "controls": "navbar",
                    "expanded": False,
                    "label": "Toggle navigation",
                },
            ):
                t.span("", class_="navbar-toggler-icon", aria={"hidden": True})
            # Below the breakpoint the navigation moves into a drawer.
            with t.dialog(
                id="navbar",
                class_="drawer drawer-end",
                tabindex=-1,
                aria={"labelledby": "navbar_label"},
            ):
                with t.div(class_="drawer-header"):
                    t.h5("Menu", class_="drawer-title", id="navbar_label")
                    t.button(
                        "",
                        type="button",
                        class_="btn-close",
                        data={"bs-dismiss": "drawer"},
                        aria={"label": "Close"},
                    )
                with t.div(class_="drawer-body"), t.ul(class_="navbar-nav"):
                    for label, anchor in navigation.items():
                        if isinstance(anchor, dict):
                            _menu(doc, label, anchor)
                        else:
                            with t.li(class_="nav-item"):
                                t.a(escape(label), href=f"#{anchor}", class_="nav-link")


def _menu(doc: DocWriter, label: str, items: Mapping[str, str]) -> None:
    t = doc.tags
    with t.li(class_="nav-item"):
        t.button(
            escape(label),
            type="button",
            class_="nav-link",
            data={"bs-toggle": "menu"},
            aria={"expanded": False},
        )
        with t.div(class_="menu"):
            for sublabel, subanchor in items.items():
                t.a(escape(sublabel), class_="menu-item", href=f"#{subanchor}")


def _vpn_unreachable(doc: DocWriter, vpn_name: str, vpn: Mapping[str, Any]) -> None:
    t = doc.tags
    if "host" in vpn and "port" in vpn:
        reason = f"{vpn['host']}:{vpn['port']} ({vpn['error']})"
    elif "socket" in vpn:
        reason = f"{vpn['socket']} ({vpn['error']})"
    else:
        reason = "network or unix socket!"

    with t.article(class_="card border-danger my-5", id=_anchor(vpn_name)):
        t.h4(escape(vpn_name), class_="card-header fg-danger")
        with t.div(class_="card-body"):
            doc(escape(f"Could not connect to {reason}"))


def _vpn_summary(
    doc: DocWriter, settings: Settings, vpn: Mapping[str, Any], vpn_mode: str
) -> None:
    t = doc.tags
    state = vpn["state"]
    stats = vpn["stats"]

    with t.li(class_="list-group-item table-responsive"):
        with t.table(class_="table table-sm"):
            with t.thead, t.tr:
                for heading in (
                    "VPN Mode",
                    "Status",
                    "Pingable",
                    "Clients",
                    "Total Bytes In",
                    "Total Bytes Out",
                    "Up Since",
                    "Local IP Address",
                ):
                    t.th(heading)
                if vpn_mode == "Client":
                    t.th("Remote IP Address")
            with t.tbody, t.tr:
                t.td(escape(str(vpn_mode)))
                t.td(escape(str(state["connected"])))
                t.td(state["success"] == "SUCCESS")
                t.td(stats["nclients"], class_="text-end")
                with t.td(class_="text-end"):
                    _data(doc, stats["bytesin"])
                with t.td(class_="text-end"):
                    _data(doc, stats["bytesout"])
                with t.td:
                    _datetime(doc, settings, state["up_since"])
                with t.td:
                    t.code(escape(str(state["local_ip"])))
                if vpn_mode == "Client":
                    with t.td:
                        t.code(escape(str(state["remote_ip"])))


def _client_traffic(doc: DocWriter, vpn: Mapping[str, Any]) -> None:
    t = doc.tags
    # A client has a single session.
    [session] = vpn["sessions"].values()
    with t.li(class_="list-group-item table-responsive"):
        with t.table(class_="table table-sm"):
            with t.thead, t.tr:
                for heading in (
                    "Tun-Tap-Read",
                    "Tun-Tap-Write",
                    "TCP-UDP-Read",
                    "TCP-UDP-Write",
                    "Auth-Read",
                ):
                    t.th(heading)
            with t.tbody, t.tr:
                for key in (
                    "tuntap_read",
                    "tuntap_write",
                    "tcpudp_read",
                    "tcpudp_write",
                    "auth_read",
                ):
                    with t.td:
                        _data(doc, session[key])


def _server_sessions(
    doc: DocWriter,
    settings: Settings,
    vpn_name: str,
    vpn: Mapping[str, Any],
    now: datetime,
) -> None:
    t = doc.tags
    show_disconnect = vpn["show_disconnect"]
    with t.li(class_="list-group-item table-responsive"):
        with t.table(
            class_="table table-sm table-striped table-hover",
            data={"sortable": True},
        ):
            with t.thead(class_="text-nowrap"), t.tr:
                for heading in (
                    "Username",
                    "VPN IP",
                    "Remote IP",
                    "Local IP",
                    "Connected Since",
                    "Last Ping",
                    "Time Online",
                ):
                    t.th(heading)
                if show_disconnect:
                    t.th("Action")
            with t.tbody:
                for session in vpn["sessions"].values():
                    client_url = f"/vpns/{vpn_name}/clients/{session['local_ip']}"
                    with t.tr:
                        with t.td:
                            t.a(escape(str(session["username"])), href=client_url)
                        with t.td:
                            t.code(escape(str(session["local_ip"])))
                        with t.td:
                            t.code(escape(str(session["remote_ip"])))
                        with t.td:
                            t.a("show", href=f"{client_url}/ip")
                        with t.td:
                            _datetime(doc, settings, session["connected_since"])
                        with t.td:
                            if "last_seen" in session:
                                _datetime(doc, settings, session["last_seen"])
                            else:
                                doc("Unknown")
                        with t.td(class_="text-end"):
                            _timedelta(doc, now - session["connected_since"])
                        if show_disconnect:
                            with t.td, t.form(method="post"):
                                _hidden(doc, "vpn_name", vpn_name)
                                if "port" in session:
                                    _hidden(doc, "ip", session["remote_ip"])
                                    _hidden(doc, "port", session["port"])
                                if "client_id" in session:
                                    _hidden(doc, "client_id", session["client_id"])
                                t.button(
                                    "Disconnect",
                                    type="submit",
                                    class_="btn-solid btn-sm theme-danger",
                                )


def _hidden(doc: DocWriter, name: str, value: object) -> None:
    v = doc.voids
    v.input(type="hidden", name=name, value=value)


def _vpn(
    doc: DocWriter,
    settings: Settings,
    vpn_name: str,
    vpn: Mapping[str, Any],
    now: datetime,
) -> None:
    t = doc.tags
    if not vpn["socket_connected"]:
        _vpn_unreachable(doc, vpn_name, vpn)
        return

    vpn_mode = vpn["state"]["mode"]
    with t.article(class_="card my-5", id=_anchor(vpn_name)):
        with t.a(href=f"/vpns/{vpn_name}", class_="fg-reset text-decoration-none"):
            t.h4(escape(vpn_name), class_="card-header")
        with t.ul(class_="list-group list-group-flush"):
            _vpn_summary(doc, settings, vpn, vpn_mode)
            if vpn_mode == "Client":
                _client_traffic(doc, vpn)
            elif vpn_mode == "Server":
                _server_sessions(doc, settings, vpn_name, vpn, now)
        t.div(escape(str(vpn["release"])), class_="card-footer fg-secondary")


def _map(doc: DocWriter) -> None:
    t = doc.tags
    v = doc.voids
    with t.article(class_="card my-5"):
        v.link(**LEAFLET_CSS)
        t.script("", **LEAFLET_JS)
        t.h3("Map View", class_="card-header")
        with t.div(class_="card-body p-0"):
            t.div("", id="map_canvas", style="height:50vh;")
            with t.script:
                doc(MAP_SCRIPT)


def render_index(
    settings: Settings,
    vpns: Mapping[str, Mapping[str, Any]],
    *,
    show_map: bool,
    now: datetime,
) -> str:
    output = StringIO()
    doc = DocWriter(output)
    navigation = {"VPNs": {vpn: _anchor(vpn) for vpn in vpns}}
    with _page(doc, settings, navigation=navigation, now=now):
        for vpn_name, vpn in vpns.items():
            _vpn(doc, settings, vpn_name, vpn, now)
        if show_map:
            _map(doc)
    return output.getvalue()


def render_vpn(
    settings: Settings, vpn_name: str, vpn: Mapping[str, Any], *, now: datetime
) -> str:
    output = StringIO()
    doc = DocWriter(output)
    with _page(doc, settings, now=now):
        _vpn(doc, settings, vpn_name, vpn, now)
    return output.getvalue()


def render_iframe(settings: Settings, address: str, *, now: datetime) -> str:
    output = StringIO()
    doc, t, _ = DocWriter(output).parts
    with _page(doc, settings, fullpage=True, now=now):
        t.iframe("", src=address, class_="w-100 h-100")
    return output.getvalue()


def render_preformatted(settings: Settings, text: str, *, now: datetime) -> str:
    output = StringIO()
    doc, t, _ = DocWriter(output).parts
    with _page(doc, settings, fullpage=True, now=now):
        # Indentation inside <pre> would show, so keep it on one line.
        with doc.inline(), t.pre:
            doc(escape(text))
    return output.getvalue()
