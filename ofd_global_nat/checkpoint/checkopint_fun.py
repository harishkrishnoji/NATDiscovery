"""Palo Alto Rules - Log Profile Update."""
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
        self.disregard_pkg = []
        self.mem_cluster_info = {}

    def domain_lst(self):
        """This function will pull all the domain from Checkpoint."""
        domains = self.cp.show_domains()
        domains_json = json.loads(domains.text)
        for domain in domains_json.get("objects"):
            self.domain_list.append(domain.get("name"))

    def cma_packages(self):
        """This function will pull all the packages from specific Domain."""
        params = {"data": {"limit": 500, "offset": 0, "details-level": "full"}}
        packages = self.cp.get_cp_data("show-packages", **params)
        packages_json = json.loads(packages.text)
        for package in packages_json.get("packages"):
            self.package = package.get("name")
            if self.package not in self.disregard_pkg:
                # This function will pull nat rulebase associated to the package in Domain/CMA
                install_targets = []
                if "all" in package.get("installation-targets"):
                    gateways = self._get_gateways_servers()
                    for device in gateways.get("objects"):
                        if device.get("type") == "CpmiVsClusterNetobj" or device.get("type") == "CpmiVsxClusterMember":
                            install_targets.append(self._parse_cpmigatewaycluster(device.get("name")))
                    # self.target = "All"
                elif package.get("installation-targets"):
                    install_targets = [self._parse_cpmigatewaycluster(device.get("name")) for device in package.get("installation-targets")]
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
            "Name": rule.get("uid"),
            "Method": rule.get("method"),
            "OriginalSource": self._convert_to_str(self.rulebase_objects.get(rule.get("original-source"))),
            "TranslatedSource": self._convert_to_str(self.rulebase_objects.get(rule.get("translated-source"))),
            "OriginalDestination": self._convert_to_str(self.rulebase_objects.get(rule.get("original-destination"))),
            "TranslatedDestination": self._convert_to_str(self.rulebase_objects.get(rule.get("translated-destination"))),
            "Firewall": f"CheckPoint[{self.env.upper()}]",
            "FirewallName": self.target,
            "Policy": self.package,
        }
        return nat_rule

    def _convert_to_str(self, item):
        if isinstance(item, list):
            return ", ".join(item)
        return item

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
            elif object.get("type") == "CpmiGatewayCluster" or object.get("type") == "CpmiHostCkp" or object.get("type") == "simple-gateway":
                self.rulebase_objects[object.get("uid")] = self._parse_cpmigatewaycluster(object.get("name"))
            else:
                # log.warning(f"Unknown Object type: {object}")
                # self.rulebase_objects[object.get("uid")] = {"name": object.get("name"), "type": object.get("type")}
                self.rulebase_objects[object.get("uid")] = object.get("name")

    def _parse_cpmigatewaycluster(self, name):
        for device in self.gateways_list:
            if device.get("hostname") == name:
                return f'{device.get("hostname")}[{device.get("mgmt_address")}]'
        return name

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

    def _get_gateways_servers(self, offset=0, level="standard"):
        params = {"data": {"limit": 500, "offset": offset, "details-level": level}}
        gateways_raw = self.cp.get_cp_data("show-gateways-and-servers", **params)
        return json.loads(gateways_raw.text)

    def gateways(self):
        """This function will pull all the gatwats from Checkpoint."""
        total = 0
        offset = 0
        while total >= offset:
            # params = {"data": {"limit": 500, "offset": offset, "details-level": "full"}}
            # gateways_raw = self.cp.get_cp_data("show-gateways-and-servers", **params)
            gateways_json = self._get_gateways_servers(offset, "full")
            total = gateways_json.get("total")
            offset = offset + 500
            gateway_server_type = [
                "CpmiGatewayCluster",
                "CpmiClusterMember",
                "CpmiVsClusterNetobj",
                "CpmiVsxClusterNetobj",
                "CpmiVsxClusterMember",
                "CpmiHostCkp",
                "simple-gateway",
            ]
            for gateways in gateways_json.get("objects"):
                if gateways.get("type") == "CpmiGatewayCluster" or gateways.get("type") == "CpmiVsxClusterNetobj":
                    for cluster_mem in gateways.get("cluster-member-names", []):
                        self.mem_cluster_info.update({cluster_mem: gateways.get("name")})
                if gateways.get("type") in gateway_server_type:
                    device_info = {"environment": f"{self.env}-cp", "tags": [self.env]}
                    for field in CP_DEVICE_FIELDS:
                        if field == "ipv4-address":
                            device_info.update({"mgmt_address": gateways.get(field)})
                        elif field == "name":
                            device_info.update({"hostname": gateways.get(field)})
                        elif field == "hardware":
                            device_info.update({"model": gateways.get(field)})
                        else:
                            device_info.update({field: gateways.get(field)})
                    self.gateways_list.append(device_info)
                if gateways.get("type") == "checkpoint-host":
                    self.checkpoint_host.update({gateways.get("name"): {"address": gateways.get("ipv4-address")}})
        log.info(f"Total Devices: {len(list(self.gateways_list))}")
        log.info("Gateway parser...")
        self._gateway_parser()

    def _gateway_parser(self):
        clusters = {}
        for device in self.gateways_list:
            if device.get("type") == "CpmiVsxClusterNetobj" or device.get("type") == "CpmiGatewayCluster":
                clusters.update({device.get("hostname"): device})
        for device in self.gateways_list:
            if device.get("type") == "CpmiClusterMember" or device.get("type") == "CpmiVsxClusterMember":
                cluster_name = self.mem_cluster_info.get(device.get("hostname"))
                if clusters.get(cluster_name):
                    device["operating-system"] = clusters[cluster_name].get("operating-system")
                    device["model"] = clusters[cluster_name].get("model")
                    device["version"] = clusters[cluster_name].get("version")
                    device["network-security-blades"] = clusters[cluster_name].get("network-security-blades")
                else:
                    log.warning(f"Cluster-Member mismatch : {device.get('hostname')}")

    def jsonfile(self, data, type):
        """Write to JSON for reference."""
        self.filename = f"RUNDECK_{self.env}_CP_{type}-{time.strftime('%m%d%Y-%H%M')}.json"
        with open(self.filename, "w+") as json_file:
            json.dump(data, json_file, indent=4, separators=(",", ": "), sort_keys=True)
