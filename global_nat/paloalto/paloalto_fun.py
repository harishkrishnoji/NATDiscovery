"""Palo Alto Rules - Log Profile Update."""
from xmltodict import parse
from helper.local_helper import log
from helper.variables_firewall import PALO_DEVICE_FIELDS


class Palo_NAT_Function:
    """Palo Alto NAT Function."""
    def __init__(self, pan, env, site) -> None:
        """Initialize Palo Alto Function Class.

        Args:
            pan (class): Main PAN Class.
            env (str): Environment.
        """
        self.device_list = []
        self.pan = pan
        self.env = env
        self.site = site
        self.nat_rules = []
        self.rules = []
        self.filename = ""
        self.db = ""

    def firewall_devices(self):
        """Get firewall device list."""
        devices = parse(self.pan.op(cmd="show devices all", xml=True))
        for device in devices["response"]["result"]["devices"].get("entry"):
            device_info = {"environment": f"{self.env}-palo-{self.site}", "tags": [self.env]}
            for field in PALO_DEVICE_FIELDS:
                if field == "ha" and "ha" in device:
                    device_info.update({field: device["ha"].get("state")})
                elif field == "vsys":
                    if isinstance(device[field]["entry"], list):
                        for vsys in device[field]["entry"]:
                            device_info.update({field: vsys.get("display-name")})
                    else:
                        device_info.update({field: device[field]["entry"].get("display-name")})
                elif field == "ip-address":
                    device_info.update({"mgmt_address": device.get(field)})
                else:
                    device_info.update({field: device.get(field)})
            self.device_list.append(device_info)

    def _rule_address_parser(self, item):
        """NAT Rule Address parser."""
        address = []
        for addr in item.strip()[:-1].split(" "):
            if addr == "any":
                return addr
            elif "." in addr:
                address.append(addr)
        return ", ".join(address)

    def _nat_policy_addresses(self, rule, device):
        """NAT Policy Addresses."""
        rule_data = {}
        for item in rule.split('\n'):
            if "index" in item:
                rule_data["Name"] = item[1:].split(";")[0].strip()
            elif "source" in item:
                rule_data["OriginalSource"] = self._rule_address_parser(item)
            elif "destination" in item:
                rule_data["OriginalDestination"] = self._rule_address_parser(item)
            rule_data["FirewallName"] = device
            rule_data["Firewall"] = f"PaloAlto[{self.env.upper()}-{self.site.upper()}]"
        return rule_data

    def _rule_translate_to_parser(self, trans_item, rule_data):
        if "src" in trans_item:
            src_lst = trans_item.split(" ")
            for src_item in src_lst:
                if "static" in src_item or "dynamic" in src_item:
                    rule_data["Method"] = src_item[1:-1]
                elif "." in src_item:
                    rule_data["TranslatedSource"] = src_item
        elif "dst" in trans_item:
            rule_data["TranslatedDestination"] = trans_item.split(" ")[1]

    def _nat_policy_translate(self, rule):
        """NAT Policy Translate"""
        rule_data = {}
        for item in rule.split('\n'):
            if "index" in item:
                rule_data["Name"] = item[1:].split(";")[0].strip()
            elif "translate-to" in item:
                # translate-to "src: 198.184.0.53 (dynamic-ip-and-port) (pool idx: 5)";
                # translate-to "dst: 10.31.216.41(cnt: 0)(distribution: round-robin)";
                translate_list = item.strip().split('"')
                # Set default to Original
                rule_data["TranslatedSource"] = "Original"
                rule_data["TranslatedDestination"] = "Original"
                for trans_item in translate_list:
                    self._rule_translate_to_parser(trans_item.replace("(cnt:", ""), rule_data)
            for rule in self.nat_rules:
                if rule.get("Name") == rule_data.get("Name"):
                    rule.update(rule_data)

    def get_nat_policy(self, cmd, device):
        """NAT Policy"""
        # for device in self.device_list:
        # if device.get("ha") == "passive" and device.get("connected") == "yes":
        resp = self.pan.op(cmd=cmd, extra_qs=f"target={device.get('serial')}", xml=True)
        if resp and "addresses" in cmd:
            log.info(device.get("hostname"))
            self.nat_rules = []
            xml_dict = parse(resp)['response']['result']
            if xml_dict:
                for rule in xml_dict.split("\n\n"):
                    rule_data = self._nat_policy_addresses(rule, f'{device.get("hostname")}[{device.get("mgmt_address")}]')
                    self.nat_rules.append(rule_data)
        elif resp:
            xml_dict = parse(resp)['response']['result']['member']
            if xml_dict:
                for rule in xml_dict.split("\n\n"):
                    self._nat_policy_translate(rule)
                self.rules.extend(self.nat_rules)
