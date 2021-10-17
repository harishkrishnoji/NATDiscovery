import json
from helper_fts.logger import get_logger

logger = get_logger("OFD NAT")
obj_dict = {}
obj_dict["any"] = "Any"
grp_m_lst = []


###########################################
#         Checkpoint Functions            #
###########################################


def get_domain_list(cp):
    """This function will pull all the domain from Checkpoint.

    Args:
        cp (hadler): Handler to make specific API calls.
    """
    domain_list_data = []
    data = cp.show_domains()
    if data.status_code == 200:
        cp_data = json.loads(data.text)
        # Save all the domain into list - domain_list_data
        for domain_list in cp_data["objects"]:
            domain_list_data.append(domain_list["name"])
        return 0, domain_list_data
    return 1, data


def get_cma_packages_list(cp):
    """This function will pull all the package from specific Domain/CMA.

    Args:
        cp (hadler): Handler to make specific API calls.
    """
    data1 = {}
    data = {"limit": 500, "offset": 0, "details-level": "full"}
    data1["data"] = data
    data = cp.get_cp_data("show-packages", **data1)
    table_data = []
    if data.status_code == 200:
        cp_data = json.loads(data.text)
        for pkg_list in cp_data["packages"]:
            # This function will pull nat rulebase associated to the package in Domain/CMA
            if "all" in pkg_list["installation-targets"]:
                target = "All"
            else:
                install_targets = []
                for device in pkg_list["installation-targets"]:
                    install_targets.append(device["name"])
                target = ", ".join(install_targets)
            table_data.append(get_nat_rulebase(cp, pkg_list["name"], target))
        return table_data


def get_group(cp, grp):
    """This function will get group info.

    Args:
        cp (hadler): Handler to make specific API calls.
        grp (str): CheckPoint group name.
    """
    global grp_m_lst
    pload = {"data": {"name": grp}}
    resp = cp.get_cp_data("show-group", **pload)
    if resp.status_code == 200:
        jresp = json.loads(resp.text)
        for mem in jresp.get("members", []):
            if mem.get("type") == "host":
                grp_m_lst.append(mem["ipv4-address"])
            elif mem.get("type") == "network":
                grp_m_lst.append(f'{mem["subnet4"]}/{mem["subnet-mask"]}')
            elif mem.get("type") == "address-range":
                grp_m_lst.append(f'{mem["ipv4-address-first"]}-{mem["ipv4-address-last"]}')
            elif mem.get("type") == "group":
                get_group(cp, mem["name"])


def parse_data(cp, pkg, cp_data, trg):
    """This function will parse the rule.

    Args:
        cp (hadler): Handler to make specific API calls.
        pkg (str): CheckPoint Package Name.
        cp_data (dict): Firewall Rules.
    """
    uid_map = {}
    table_data = []
    # if "objects-dictionary" in cp_data:
    if cp_data.get("objects-dictionary"):
        # for obj_dict in cp_data["objects-dictionary"]:
        for obj_dict in cp_data.get("objects-dictionary"):
            # if "host" in obj_dict["type"]:
            if obj_dict.get("type") == "host":
                uid_map[obj_dict.get("uid")] = obj_dict.get("ipv4-address")
            elif "address-range" in obj_dict["type"]:
                uid_map[obj_dict["uid"]] = f"{obj_dict['ipv4-address-first']}-{obj_dict['ipv4-address-last']}"
            elif obj_dict["type"] == "network":
                uid_map[obj_dict["uid"]] = f"{obj_dict['subnet4']}/{obj_dict['subnet-mask']}"
            elif obj_dict.get("type") == "group":
                global grp_m_lst
                grp_m_lst = []
                get_group(cp, obj_dict["name"])
                uid_map[obj_dict["uid"]] = grp_m_lst
            else:
                uid_map[obj_dict["uid"]] = obj_dict["name"]
    for rule_dict in cp_data.get("rulebase"):
        # these are NAT rules with sections
        if "rulebase" in rule_dict:
            for rule_dict1 in rule_dict.get("rulebase"):
                table_data.append(nat_var(rule_dict1, uid_map, pkg, trg))
        else:
            table_data.append(nat_var(rule_dict, uid_map, pkg, trg))

    return table_data


def nat_var(rule_dict1, uid_map, pkg, trg):
    """Variable function.

    Args:
        uid_map (dict): UID to IP address.
        pkg (str): CheckPoint Package Name.
        rule_dict1 (dict): Firewall Rules.
    """
    var = {
        "Method": rule_dict1["method"],
        "Original-Source": uid_map.get(rule_dict1["original-source"]),
        "Translated-Source": uid_map.get(rule_dict1["translated-source"]),
        "Original-Destination": uid_map.get(rule_dict1["original-destination"]),
        "Translated-Destination": uid_map.get(rule_dict1["translated-destination"]),
        "Firewall": "CheckPoint",
        "Firewall-Name": trg,
        "Policy": pkg,
    }
    return var


def get_nat_rulebase(cp, pkg, trg):
    """To pull NAT Rulebase for given Package.

    Args:
        cp (hadler): Handler to make specific API calls.
        pkg (str): CheckPoint Package Name.
    """
    j = 0
    table_data = []
    total_rule = 0
    while j <= total_rule:
        data = {}
        data["limit"] = 500
        data["offset"] = 0 + j
        data["details-level"] = "standard"
        data["use-object-dictionary"] = "true"
        data["package"] = pkg
        data2 = {"data": data}
        data1 = cp.get_cp_data("show-nat-rulebase", **data2)
        if data1.status_code == 200:
            cp_data = json.loads(data1.text)
            total_rule = cp_data["total"]
        if total_rule == 0:
            j = j + 1
        else:
            table_data.extend(parse_data(cp, pkg, cp_data, trg))
            j = j + 500
    logger.info(f"\t\tPackages : {(pkg)} ({total_rule})")
    return table_data
