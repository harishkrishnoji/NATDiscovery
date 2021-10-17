import os
from helper_fts.logger import get_logger
import requests

logger = get_logger("OFD NAT")
outnat = []
obj_dict = {}
tag_lst = []


###########################################
#           PaloAlto Functions            #
###########################################


def get_gp_lst(pan, xpaths):
    """Get the Object group list from Panorama and parase those object groups.

    Args:
        pan (hadler): Handler to make specific API calls.
        xpath (str): URI.
    """
    kwargs = {}
    kwargs["type"] = "config"
    kwargs["action"] = "get"
    kwargs["xpath"] = xpaths
    resp = pan.get_pam_data(**kwargs)

    if resp["response"]["result"] is None or resp["response"]["result"]["address-group"] is None:
        pass
    else:
        for obj in resp["response"]["result"]["address-group"]["entry"]:
            if "static" in obj:
                obj1_lst = []
                if obj != "static":
                    if isinstance(obj["static"]["member"], str):
                        if obj["static"]["member"] in obj_dict.keys():
                            obj_dict[obj["@name"]] = obj_dict[obj["static"]["member"]]
                        else:
                            obj_dict[obj["@name"]] = obj["static"]["member"]
                    else:
                        for member in obj["static"]["member"]:
                            if member in obj_dict.keys():
                                obj1_lst.append(obj_dict[member])
                            else:
                                obj1_lst.append(member)
                        obj_dict[obj["@name"]] = ",".join(obj1_lst)
            elif "dynamic" in obj:
                obj1_lst = []
                tmp = []
                for i in tag_lst:
                    if obj != "dynamic":
                        if " or " in obj["dynamic"]["filter"]:
                            tmp = obj["dynamic"]["filter"].split(" or ")
                        else:
                            tmp = obj["dynamic"]["filter"].split(" and ")
                        if obj["dynamic"]["filter"].strip("'") in i["tag"]:
                            obj1_lst.append(i["address"])
                        for x in tmp:
                            if str(x).strip("'") in i["tag"]:
                                obj1_lst.append(i["address"])
                        obj_dict[obj["@name"]] = ",".join(obj1_lst)


def search_list(source):
    """Get the Objects IPs.

    Args:
        source (dict): IP Dict.
    """
    s_lst = []
    if isinstance(source, list):
        for i in source:
            if i in obj_dict.keys():
                s_lst.append(obj_dict[i])
    else:
        if source in obj_dict.keys():
            s_lst.append(obj_dict[source])
    return s_lst


def get_device_group_lst(pan):
    """Get Device group list from Panorama.

    Args:
        pan (hadler): Handler to make specific API calls.
    """
    dg_lst = []
    kwargs = {}
    kwargs["type"] = "op"
    kwargs["cmd"] = "<show><devicegroups></devicegroups></show>"
    resp = pan.get_pam_data(**kwargs)
    for dev in resp["response"]["result"]["devicegroups"]["entry"]:
        if "devices" in dev:
            if isinstance(dev["devices"]["entry"], list):
                dev1 = []
                for j in dev["devices"]["entry"]:
                    dev1.append(j["hostname"])
                dg_lst.append({"device": dev["@name"], "hostname": ", ".join(dev1)})
            else:
                dg_lst.append({"device": dev["@name"], "hostname": dev["devices"]["entry"]["hostname"]})
    return dg_lst


def append_rule(rule, site, dg):
    """Write all the rules to file.

    Args:
        rule (str): Rule which need to be parsed and written to csv.
        site (str): PAN region info.
        dg (dict): Device group.
    """
    st_lst = []
    dt_lst = []
    method = None
    src_lst = search_list(rule["source"]["member"])
    if not src_lst:
        src_lst.append(rule["source"]["member"])

    dst_lst = search_list(rule["destination"]["member"])
    if not dst_lst:
        dst_lst.append(rule["destination"]["member"])

    if "source-translation" in rule.keys():
        if "dynamic-ip-and-port" in rule["source-translation"].keys():
            if "interface-address" in rule["source-translation"]["dynamic-ip-and-port"].keys():
                st_lst.append(rule["source-translation"]["dynamic-ip-and-port"]["interface-address"]["interface"])
                method = "source-dynamic-interface"
            if "translated-address" in rule["source-translation"]["dynamic-ip-and-port"].keys():
                st_lst = search_list(rule["source-translation"]["dynamic-ip-and-port"]["translated-address"]["member"])
                if st_lst == []:
                    st_lst.append(rule["source-translation"]["dynamic-ip-and-port"]["translated-address"]["member"])
                method = "source-dynamic-address"
        if "static-ip" in rule["source-translation"].keys():
            st_lst = search_list(rule["source-translation"]["static-ip"]["translated-address"])
            if st_lst == []:
                st_lst.append(rule["source-translation"]["static-ip"]["translated-address"])
            method = "source-static"
        if "dynamic-ip" in rule["source-translation"].keys():
            st_lst = search_list(rule["source-translation"]["dynamic-ip"]["translated-address"]["member"])
            if st_lst == []:
                st_lst.append(rule["source-translation"]["dynamic-ip"]["translated-address"]["member"])
            method = "source-dynamic-ip"

    if "dynamic-destination-translation" in rule.keys():
        dt_lst = search_list(rule["dynamic-destination-translation"]["translated-address"])
        if dt_lst == []:
            dt_lst.append(rule["dynamic-destination-translation"]["translated-address"])
        method = "dynamic-destination"

    if "destination-translation" in rule.keys():
        dt_lst = search_list(rule["destination-translation"]["translated-address"])
        if dt_lst == []:
            dt_lst.append(rule["destination-translation"]["translated-address"])
        method = "static-destination"

    outnat.append(
        {
            "Firewall": f"Palo Alto-{site}",
            "Policy": str(dg["device"]),
            "Original-Source": ", ".join(map(str, src_lst)),
            "Original-Destination": ", ".join(map(str, dst_lst)),
            "Method": method,
            "Firewall-Name": str(dg["hostname"]),
            "Translated-Source": ", ".join(map(str, st_lst)),
            "Translated-Destination": ", ".join(map(str, dt_lst)),
        }
    )


def get_nat_lst(pan, xpaths, site, dg):
    """Rulebase nat list.

    Args:
        xpaths (str): xpath for APIClient.
        dg (dict): device group.
        pan (hadler): Handler to make specific API calls.
        xpath (str): URI.
    """
    kwargs = {}
    kwargs["type"] = "config"
    kwargs["action"] = "get"
    kwargs["xpath"] = xpaths
    resp = pan.get_pam_data(**kwargs)
    if resp["response"]["result"] is not None:
        if resp["response"]["result"]["nat"]["rules"] is not None:
            if resp["response"]["result"]["nat"]["rules"]["entry"] is not None:
                ru = resp["response"]["result"]["nat"]["rules"]["entry"]
                if isinstance(ru, list):
                    for rule in ru:
                        if "disabled" not in rule:
                            append_rule(rule, site, dg)
                else:
                    if "disabled" not in ru:
                        append_rule(ru, site, dg)


def get_address(pan, xpaths):
    """Get the Object list from Panorama and parase those objects.

    Args:
        xpaths (str): xpath for APIClient.
        pan (hadler): Handler to make specific API calls.
    """
    kwargs = {}
    kwargs["type"] = "config"
    kwargs["action"] = "get"
    kwargs["xpath"] = xpaths
    resp = pan.get_pam_data(**kwargs)
    if resp["response"]["result"] is None or resp["response"]["result"]["address"] is None:
        pass
    else:
        if isinstance(resp["response"]["result"]["address"]["entry"], list):
            for obj in resp["response"]["result"]["address"]["entry"]:
                if "ip-netmask" in obj:
                    obj_dict[obj["@name"]] = obj["ip-netmask"]
                    if "tag" in obj and obj["tag"] is not None:
                        tag_lst.append(
                            {"name": obj["@name"], "address": obj["ip-netmask"], "tag": obj["tag"]["member"]}
                        )
                elif "ip-range" in obj:
                    obj_dict[obj["@name"]] = obj["ip-range"]
                    if "tag" in obj:
                        tag_lst.append({"name": obj["@name"], "address": obj["ip-range"], "tag": obj["tag"]["member"]})
                elif "fqdn" in obj:
                    obj_dict[obj["@name"]] = obj["fqdn"]
                    if "tag" in obj:
                        tag_lst.append({"name": obj["@name"], "address": obj["fqdn"], "tag": obj["tag"]["member"]})
        else:
            if "ip-netmask" in resp["response"]["result"]["address"]["entry"]:
                obj_dict[resp["response"]["result"]["address"]["entry"]["@name"]] = resp["response"]["result"][
                    "address"
                ]["entry"]["ip-netmask"]
                if "tag" in resp["response"]["result"]["address"]["entry"]:
                    tag_lst.append(
                        {
                            "name": resp["response"]["result"]["address"]["entry"]["@name"],
                            "address": resp["response"]["result"]["address"]["entry"]["ip-netmask"],
                            "tag": resp["response"]["result"]["address"]["entry"]["tag"]["member"],
                        }
                    )
            elif "ip-range" in resp["response"]["result"]["address"]["entry"]:
                obj_dict[resp["response"]["result"]["address"]["entry"]["@name"]] = resp["response"]["result"][
                    "address"
                ]["entry"]["ip-range"]
                if "tag" in resp["response"]["result"]["address"]["entry"]:
                    tag_lst.append(
                        {
                            "name": resp["response"]["result"]["address"]["entry"]["@name"],
                            "address": resp["response"]["result"]["address"]["entry"]["ip-range"],
                            "tag": resp["response"]["result"]["address"]["entry"]["tag"]["member"],
                        }
                    )


###########################################
#              File Upload                #
###########################################


def uploadfile(fname):
    """Upload file to remote server.

    Args:
        filename (str): Filename which need to be uploaded
    """

    url = "https://sas-automation.1dc.com/cgi-bin/uploadfile.py"
    files = [("filename", (os.path.basename(fname), open(fname, "rb")))]
    response = requests.request("POST", url, files=files, verify=False)
    return response.text
