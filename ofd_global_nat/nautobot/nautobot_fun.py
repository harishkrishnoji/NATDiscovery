# pylint: disable=W1203, C0103, W0631, W0703
"""Nautobot REST API SDK."""

# import os
import requests
import pynautobot
from helper.variables_nautobot import NAUTOBOT_DEVICE_REGION, NAUTOBOT_DEVICE_REGION_OFS, DEVICE_ROLE
from helper.local_helper import log

requests.urllib3.disable_warnings()


class SANE_DEVICE:
    """Create a Nautobot LB Device Function client."""

    def __init__(self, device_data="", url="", token=""):
        """Initialize Nautobot Function Client.

        Args:
            url (str): Nautobot URL.
            token (str): Nautobot Token.
            device_data (dict): LB Device information in dict format.
                ex: device_data = {
                        "environment": "ofd-palo",
                        "hostname": "USOMA01FWLCLT01B",
                        "mgmt_address": "10.243.96.155",
                        "model": "PA-VM",
                        "serial": "007251000204254",
                        "sw-version": "9.1.11",
                        "tags": ["ofd"],
                    },
        """
        self.nb                      = pynautobot.api(url, token=token, threading=True)
        self.nb.http_session.verify  = False
        self.device_data             = device_data
        self.plugins_attr            = getattr(self.nb, "plugins")
        self.extras_attr             = getattr(self.nb, "extras")
        self.dcim_attr               = getattr(self.nb, "dcim")
        self.ipam_attr               = getattr(self.nb, "ipam")
        self.tags_attr               = getattr(self.extras_attr, "tags")
        self.ip_addresses_attr       = getattr(self.ipam_attr, "ip-addresses")
        self.interfaces_attr         = getattr(self.dcim_attr, "interfaces")
        self.sites_attr              = getattr(self.dcim_attr, "sites")
        self.devices_attr            = getattr(self.dcim_attr, "devices")
        self.device_types_attr       = getattr(self.dcim_attr, "device-types")
        self.device_roles_attr       = getattr(self.dcim_attr, "device-roles")
        self.manufacturers_attr      = getattr(self.dcim_attr, "manufacturers")
        self.regions_attr            = getattr(self.dcim_attr, "regions")
        self.platforms_attr          = getattr(self.dcim_attr, "platforms")

    def device(self):
        """Check if loadbalancer object exist in core Device module."""
        device = self.devices_attr.get(name=self.device_data.get("hostname"))
        self.tags()
        if not device:
            self.device_role()
            self.device_type()
            self.site()
            self.device_platforms()
            data = {
                "name": self.device_data.get("hostname"),
                "device_type": self.device_type_uuid,
                "device_role": self.device_role_uuid,
                "platform": self.platform_uuid,
                "site": self.site_uuid,
                "status": "active",
                "tags": self.tag_uuid,
                "serial": self.device_data.get("serial")
            }
            device = self.devices_attr.create(data)
            self.loadbalancer_uuid = device.id
            self.device_interface()
        self.loadbalancer_uuid = device.id

    def device_interface(self):
        """Create Device Interface object in core Organization module."""
        interface = self.interfaces_attr.filter(device=self.device_data.get("hostname"))
        if interface:
            self.interface_uuid = interface[0].id
        else:
            data = {
                "device": self.loadbalancer_uuid,
                "name": "Management",
                "type": "virtual",
                "enabled": True,
                "description": f"{self.device_data.get('hostname')} Management Interface"
            }
            interface = self.interfaces_attr.create(data)
            self.interface_uuid = interface.id
        self.device_interface_address()

    def device_interface_address(self):
        """Create Interface Address object in core Organization module."""
        self.mgmt_address_uuid = self.ipam_address(self.device_data.get("mgmt_address"))
        data = {"primary_ip4": self.mgmt_address_uuid, "tags": self.tag_uuid}
        device = self.devices_attr.get(name=self.device_data.get("hostname"))
        device.update(data)

    def device_role(self):
        """Create Device Role object in core Organization module."""
        device_role = self.device_roles_attr.get(name="firewall")
        if not device_role:
            data = DEVICE_ROLE
            device_role = self.device_roles_attr.create(data)
        self.device_role_uuid = device_role.id

    def device_platforms(self):
        """Create Device Platform object in core Organization module."""
        name = "gaia" if "-cp" in self.device_data.get("environment") else "panos"
        platform = self.platforms_attr.get(name=name)
        if not platform:
            data = {"name": name, "slug": name, "manufacturer": self.manufacturer_uuid}
            platform = self.platforms_attr.create(data)
        self.platform_uuid = platform.id

    def device_type(self):
        """Create Device Type object in core Organization module."""
        device_type = self.device_types_attr.get(slug="firewall")
        if not device_type:
            self.manufacturers()
            data = {
                "manufacturer": self.manufacturer_uuid,
                "model": self.device_data.get("model"),
                "slug": "firewall",
            }
            device_type = self.device_types_attr.create(data)
        self.device_type_uuid = device_type.id

    def manufacturers(self):
        """Create manufacturer object in core Organization module."""
        manufacturer_name = "CheckPoint" if "-cp" in self.device_data.get("environment") else "PaloAltoNetworks"
        manufacturer = self.manufacturers_attr.get(name=manufacturer_name)
        if not manufacturer:
            data = {"name": manufacturer_name, "slug": self.slug_parser(manufacturer_name)}
            manufacturer = self.manufacturers_attr.create(data)
        self.manufacturer_uuid = manufacturer.id

    def tags(self):
        """Create tag object in core Organization module."""
        tag_uuid = []
        for tag_name in self.device_data.get("tags"):
            tag = self.tags_attr.get(slug=self.slug_parser(tag_name))
            if not tag:
                data = {"name": tag_name.lower(), "slug": self.slug_parser(tag_name)}
                tag = self.tags_attr.create(data)
            tag_uuid.append(tag.id)
        self.tag_uuid = tag_uuid

    def site(self):
        """Create Site object in core Organization module."""
        self.site_info = NAUTOBOT_DEVICE_REGION.get("SANE_UNK")
        if "ofd" in self.device_data.get("tags"):
            lb_dkey = self.device_data.get("hostname")[:6]
            if lb_dkey in NAUTOBOT_DEVICE_REGION.keys():
                self.site_info = NAUTOBOT_DEVICE_REGION[lb_dkey]
        elif "ofs" in self.device_data.get("tags"):
            octate = ".".join(self.device_data.get("address").split(".", 2)[:2])
            if octate in NAUTOBOT_DEVICE_REGION_OFS.keys():
                self.site_info = NAUTOBOT_DEVICE_REGION_OFS[octate]
        site = self.sites_attr.get(slug=self.slug_parser(self.site_info.get("site")))
        if not site:
            self.region()
            data = {
                "name": self.site_info.get("site"),
                "slug": self.slug_parser(self.site_info.get("site")),
                "status": "active",
                "region": self.region_uuid,
                "description": self.site_info.get("description", ""),
            }
            site = self.sites_attr.create(data)
        self.site_uuid = site.id

    def region(self):
        """Create Region object in core Organization module."""
        region = self.regions_attr.get(name=self.site_info.get("region"))
        if not region:
            data = {"name": self.site_info.get("region"), "slug": self.slug_parser(self.site_info.get("region"))}
            region = self.regions_attr.create(data)
        self.region_uuid = region.id

    def ipam_address(self, address):
        """Create Interface Address object in core IPAM module.

        Args:
            address (str): IP Address.

        Returns:
            str: IP Address UUID.
        """
        ipam_addr = self.ip_addresses_attr.filter(address=address)
        ipam_address = False
        for addr in ipam_addr:
            tag = [i.slug for i in addr.tags]
            if address == addr.address.split("/")[0] and set(self.device_data.get("tags")).issuperset(set(tag)):
                ipam_address = addr
        data = dict(
            [
                ("address", address),
                ("status", "active"),
                ("tags", self.tag_uuid),
                ("assigned_object_type", "dcim.interface"),
                ("assigned_object_id", self.interface_uuid)
            ]
        )
        try:
            if not ipam_address:
                ipam_address = self.ip_addresses_attr.create(data)
            elif ipam_address.assigned_object_id != self.interface_uuid:
                ipam_address.update(data)
        except Exception as err:
            log.error(f"[{self.device_data.get('hostname')}] {address} : {err}")
        return ipam_address.id

    def slug_parser(self, name):
        """Slug name parser.

        Replace all special characters and space with "_" and covert to lower case.

        Args:
            name (str): Object name.

        Returns:
            str: Object name.
        """
        return name.replace(" ", "-").replace(".", "_").replace("*", "").replace("/", "_").lower()
