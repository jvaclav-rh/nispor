# SPDX-License-Identifier: Apache-2.0

from .base_iface import NisporBaseIface


class NisporIpTunnel(NisporBaseIface):
    def __init__(self, info):
        super().__init__(info)
        self._ip_tunnel_info = self._info.get("iptunnel", {})

    @property
    def mode(self):
        return self._ip_tunnel_info["mode"]

    @property
    def parent(self):
        return self._ip_tunnel_info["parent"]

    @property
    def local(self):
        return self._ip_tunnel_info["local"]

    @property
    def remote(self):
        return self._ip_tunnel_info["remote"]

    @property
    def ttl(self):
        return self._ip_tunnel_info["ttl"]

    @property
    def tos(self):
        return self._ip_tunnel_info["tos"]

    @property
    def flags(self):
        return self._ip_tunnel_info["flags"]

    @property
    def pmtu_disc(self):
        return self._ip_tunnel_info["pmtu_disc"]

    @property
    def encap_limit(self):
        return self._ip_tunnel_info["encap_limit"]

    @property
    def flow_label(self):
        return self._ip_tunnel_info["flow_label"]

    @property
    def encap_type(self):
        return self._ip_tunnel_info["encap_type"]

    @property
    def encap_flags(self):
        return self._ip_tunnel_info["encap_flags"]

    @property
    def encap_source_port(self):
        return self._ip_tunnel_info["encap_source_port"]

    @property
    def encap_destination_port(self):
        return self._ip_tunnel_info["encap_destination_port"]

    @property
    def collect_metadata(self):
        return self._ip_tunnel_info["collect_metadata"]

    @property
    def fwmark(self):
        return self._ip_tunnel_info["fwmark"]
