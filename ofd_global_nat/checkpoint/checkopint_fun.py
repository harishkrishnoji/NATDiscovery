"""Palo Alto Rules - Log Profile Update."""
import os
import re
import time
import json
from ipaddress import IPv4Network
from helper.local_helper import log
from helper.variables_firewall import CP_DEVICE_FIELDS


class CP_NAT_Function:
    """CheckPoint NAT Function."""

    def __init__(self, cp, env) -> None:
        self.cp = cp
        self.env = env
        self.domain_list = []
        self.gateways_list = []
        self.target = False
        self.package = False
        self.rulebase = False
        self.rulebase_objects = {}
        self.group_members = []
        self.nat_rules = []
        self.checkpoint_host = {}
        self.filename = ""

    def _domain_list(self):
        """This function will pull all the domain from Checkpoint."""
        domains = self.cp.show_domains()
        domains_json = json.loads(domains.text)
        for domain in domains_json.get("objects"):
            self.domain_list.append(domain.get("name"))

    def _cma_packages(self):
        """This function will pull all the packages from specific Domain."""
        params = {"data": {"limit": 500, "offset": 0, "details-level": "full"}}
        packages = self.cp.get_cp_data("show-packages", **params)
        packages_json = json.loads(packages.text)
        for package in packages_json.get("packages"):
            # This function will pull nat rulebase associated to the package in Domain/CMA
            self.package = package.get("name")
            if "all" in package.get("installation-targets"):
                self.target = "All"
            else:
                install_targets = [device.get("name") for device in package.get("installation-targets")]
                self.target = ", ".join(install_targets)
            self._nat_rulebase()

    def _nat_rulebase(self):
        """To pull NAT Rulebase for given Package."""
        params = {"data": {"limit": 500, "offset": 0, "details-level": "standard", "use-object-dictionary": "true", "package": self.package}}
        offset_nu = 0
        total_rule = 0
        while offset_nu <= total_rule:
            params['data']['offset'] = 0 + offset_nu
            rulebase = self.cp.get_cp_data("show-nat-rulebase", **params)
            if rulebase.status_code == 200:
                self.rulebase = json.loads(rulebase.text)
                total_rule = self.rulebase.get("total")
            if total_rule == 0:
                offset_nu = offset_nu + 1
            else:
                self._parse_nat_rulebase()
                offset_nu = offset_nu + 500
        log.info(f"Packages : {self.package} [{total_rule}]")

    def _parse_nat_rulebase(self):
        """This function will parse the rule from rulebase."""
        self._parse_rulebase_objects()
        for rules in self.rulebase.get("rulebase"):
            # these are NAT rules with sections
            if "rulebase" in rules:
                for rule in rules.get("rulebase"):
                    self.nat_rules.append(self._parser_nat_rule(rule))
            else:
                self.nat_rules.append(self._parser_nat_rule(rules))

    def _parser_nat_rule(self, rule):
        """This function will parse NAT Rule into standard dictionary.

        Args:
            rule (dict): Firewall Rule.
        """
        nat_rule = {
            "name": rule.get("uid"),
            "Method": rule.get("method"),
            "Original-Source": self.rulebase_objects.get(rule.get("original-source")),
            "Translated-Source": self.rulebase_objects.get(rule.get("translated-source")),
            "Original-Destination": self.rulebase_objects.get(rule.get("original-destination")),
            "Translated-Destination": self.rulebase_objects.get(rule.get("translated-destination")),
            "Firewall": "CheckPoint",
            "Firewall-Name": self.target,
            "Policy": self.package,
        }
        return nat_rule

    def _parse_address(self, object):
        """This function will extract IP address from string.

        Args:
            object (str): Sting value.

        Returns:
            str: IP Address if found or string.
        """
        pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        match = pattern.search(object)
        if match:
            return match[0]
        log.warning(f"Unknown Address: {object}")
        return object

    def _parse_rulebase_objects(self):
        """This function will parse the objects in rulebase."""
        for object in self.rulebase.get("objects-dictionary", []):
            if object.get("type") == "host":
                self.rulebase_objects[object.get("uid")] = object.get("ipv4-address")
            elif "address-range" in object.get("type"):
                self.rulebase_objects[object.get("uid")] = f"{object.get('ipv4-address-first')}-{object.get('ipv4-address-last')}"
            elif object.get("type") == "network":
                self.rulebase_objects[object.get("uid")] = f"{object.get('subnet4')}/{IPv4Network((0, object.get('subnet-mask'))).prefixlen}"
            elif object.get("type") == "group":
                self.group_members = []
                self._get_group(object.get("name"))
                if not self.rulebase_objects.get(object.get("uid")):
                    self.rulebase_objects[object.get("uid")] = self.group_members
            elif object.get("name") == "Any" or object.get("name") == "Original":
                self.rulebase_objects[object.get("uid")] = object.get("name")
            elif object.get("type") == "checkpoint-host":
                self.rulebase_objects[object.get("uid")] = self.checkpoint_host[object.get("name")].get("address")
            elif object.get("type") == "CpmiGatewayPlain":
                self.rulebase_objects[object.get("uid")] = self._parse_address(object.get("name"))          
            else:
                # log.warning(f"Unknown Object type: {object}")
                self.rulebase_objects[object.get("uid")] = {"name": object.get("name"), "type": object.get("type")}

    def _get_group(self, group_name):
        """This function will get group info.

        Args:
            group_name (str): CheckPoint group name.
        """
        params = {"data": {"name": group_name}}
        group = self.cp.get_cp_data("show-group", **params)
        group_json = json.loads(group.text)
        for mem in group_json.get("members", []):
            if mem.get("type") == "host":
                self.group_members.append(mem.get("ipv4-address"))
            elif mem.get("type") == "network":
                # self.group_members.append(f'{mem.get("subnet4")}/{mem.get("subnet-mask")}')
                self.group_members.append(f"{mem.get('subnet4')}/{IPv4Network((0, mem.get('subnet-mask'))).prefixlen}")
            elif mem.get("type") == "address-range":
                self.group_members.append(f'{mem.get("ipv4-address-first")}-{mem.get("ipv4-address-last")}')
            elif mem.get("type") == "group":
                self._get_group(mem["name"])

    def _gateways_list(self):
        """This function will pull all the gatwats from Checkpoint."""
        params = {"data": {"limit": 500, "offset": 0, "details-level": "full"}}
        gateways = self.cp.get_cp_data("show-gateways-and-servers", **params)
        gateways_json = json.loads(gateways.text)
        for gateways in gateways_json.get("objects"):
            if gateways.get("type") == "CpmiGatewayCluster" or gateways.get("type") == "CpmiClusterMember":
                device_info = {"environment": f"{self.env}-cp", "tags": [self.env]}
                for field in CP_DEVICE_FIELDS:
                    if field == "ipv4-address":
                        device_info.update({"mgmt_address":gateways.get(field)})
                    elif field == "name":
                        device_info.update({"hostname":gateways.get(field)})
                    elif field == "hardware":
                        device_info.update({"model":gateways.get(field)})
                    else:
                        device_info.update({field:gateways.get(field)})
                self.gateways_list.append(device_info)
            if gateways.get("type") == "checkpoint-host":
                self.checkpoint_host.update({gateways.get("name"):{"address":gateways.get("ipv4-address")}})
        log.info("Gateway parser...")
        self._gateway_parser()

    def _gateway_parser(self):
        cluster = []
        for device in self.gateways_list:
            if "CpmiGatewayCluster" in device.get("type"):
                cluster.append(device)
        for dev in cluster:
            for device in self.gateways_list:
                if dev.get("hostname") in device.get("hostname"):
                    device["operating-system"] = dev.get("operating-system")
                    device["model"] = dev.get("model")
                    device["version"] = dev.get("version")
                    device["network-security-blades"] = dev.get("network-security-blades")

    def _json_file(self, data, type):
        """Write to JSON for reference."""
        self.filename = f"RUNDECK_{self.env}_CP_{type}-{time.strftime('%m%d%Y-%H%M')}.json"
        with open(self.filename, "w+") as json_file:
            json.dump(data, json_file, indent=4, separators=(",", ": "), sort_keys=True)
