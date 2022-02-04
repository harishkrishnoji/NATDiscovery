"""Palo Alto Rules - Log Profile Update."""
import os
import time
import json
from xmltodict import parse
from helper.local_helper import log, MongoDB, uploadfile
from helper.variables_firewall import PALO_DEVICE_FIELDS

dbp = os.environ.get("RD_OPTION_DB_PWD")
dbu = os.environ.get("RD_OPTION_DB_USER")
dbh = os.environ.get("RD_OPTION_DB_HOST")
db = MongoDB(dbu, dbp, dbh)


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

    def _firewall_devices(self):
        """Get firewall device list."""
        devices = parse(self.pan.op(cmd="show devices all", xml=True))
        for device in devices["response"]["result"]["devices"].get("entry"):
            device_info = {"environment": f"{self.env}-palo-{self.site}", "tags": [self.env]}
            for field in PALO_DEVICE_FIELDS:
                if field == "ha":
                    device_info.update({field:device["ha"].get("state")})
                elif field == "vsys":
                    device_info.update({field:device[field]["entry"].get("display-name")})
                elif field == "ip-address":
                    device_info.update({"mgmt_address":device.get(field)})
                else:
                    device_info.update({field:device.get(field)})
            self.device_list.append(device_info)
        self._json_file(self.device_list, "DEVICE")
 
    def _json_file(self, data, type):
        """Write to JSON for reference."""
        self.filename = f"RUNDECK_OFD_PALO_{type}-{time.strftime('%m%d%Y-%H%M')}.json"
        with open(self.filename, "w+") as json_file:
            json.dump(data, json_file, indent=4, separators=(",", ": "), sort_keys=True)

    def _rule_address_parser(self, item):
        """NAT Rule Address parser.

        Args:
            item (str): NAT address string.

        Returns:
            list: Address list.
        """
        address = []
        for addr in item.strip()[:-1].split(" "):
            if addr == "any":
                return addr
            elif "." in addr:
                address.append(addr)
        return address


    def _nat_policy_addresses(self, rule, device):
        """NAT Policy Addresses."""
        rule_data = {}
        for item in rule.split('\n'):
            if "index" in item:
                rule_data["name"] = item[1:].split(";")[0].strip()
            elif "source" in item:
                rule_data["Original-Source"] = self._rule_address_parser(item)
            elif "destination" in item:
                rule_data["Original-Destination"] = self._rule_address_parser(item)
            rule_data["Firewall-Name"] = device
            rule_data["Firewall"] = "PaloAlto"
        return rule_data


    def _rule_translate_to_parser(self, trans_item, rule_data):
        if "src" in trans_item:
            src_lst = trans_item.split(" ")
            for src_item in src_lst:
                if "static" in src_item or "dynamic" in src_item:
                    rule_data["Method"] = src_item[1:-1]
                elif "." in src_item:
                    rule_data["Translated-Source"] = src_item
        elif "dst" in trans_item:
            rule_data["Translated-Destination"] = trans_item.split(" ")[1]

    def _nat_policy_translate(self, rule):
        """NAT Policy Translate"""
        rule_data = {}
        for item in rule.split('\n'):
            if "index" in item:
                rule_data["name"] = item[1:].split(";")[0].strip()
            elif "translate-to" in item:
                # translate-to "src: 198.184.0.53 (dynamic-ip-and-port) (pool idx: 5)";
                translate_list = item.strip().split('"')
                # Set default to Original
                rule_data["Translated-Source"] = "Original"
                rule_data["Translated-Destination"] = "Original"
                for trans_item in translate_list:
                    self._rule_translate_to_parser(trans_item, rule_data)
            for rule in self.nat_rules:
                if rule.get("name") == rule_data.get("name"):
                    rule.update(rule_data)
                    db.nat_collection(rule)

    def _get_nat_policy(self, cmd):
        """NAT Policy"""
        for device in self.device_list:
            if device.get("ha") == "passive" and device.get("connected") == "yes" and device.get("hostname") == "INBOM1FWLINT01B":
                resp = self.pan.op(cmd=cmd, extra_qs=f"target={device.get('serial')}", xml=True)
                if "addresses" in cmd:
                    self.nat_rules = []
                    xml_dict = parse(resp)['response']['result']
                    for rule in xml_dict.split("\n\n"):
                        rule_data = self._nat_policy_addresses(rule, device.get("hostname"))
                        self.nat_rules.append(rule_data)
                else: 
                    xml_dict = parse(resp)['response']['result']['member']
                    for rule in xml_dict.split("\n\n"):
                        self._nat_policy_translate(rule)
                    self.rules.extend(self.nat_rules)

    def _nat_policy(self):
        """NAT Policy."""
        self._get_nat_policy("show running nat-policy-addresses")
        self._get_nat_policy("show running nat-policy")
        for device in self.device_list:
            db.host_collection(device)
        self._json_file(self.rules, "NAT")
        resp = uploadfile(self.filename)
        log.info(resp.strip())
