# coding: utf-8

from cmath import e
from re import I
from pycti import OpenCTIApiClient
import requests
import json
import validators
# from dotenv import load_dotenv
# load_dotenv()
key_searchs = ["apt", "apt28", "botnet", "cnc", "malware", "keylogger"]
api_url = "https://ti.safegate.vn"
api_token = "456a805f-2a4c-4c8a-ac74-08813da3c1a0"
data_record = []
ip_forward = "0.0.0.0"


def observables(api_url, api_token, search_key):
    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)
    # observables = opencti_api_client.stix_cyber_observable.list(
    #     search=search_key)
    observable = opencti_api_client.stix_cyber_observable.read(
        filters=[{"key": "Label", "values": search_key}]
    )
    return observables


def convert_record_dns(list_record):
    records = ""
    for record_object in list_record:
        record = "IP DOMAIN\n"
        record = record.replace("DOMAIN", record_object['DOMAIN'])
        record = record.replace("IP", record_object['IP'])
        records += record
    return records


def writefile(data, path):
    f = open(path, "w+")
    f.write(data)
    f.close()


def parse_dns_bind(data):
    for object in data:
        return


def update_record():
    data_record = []
    for search in key_searchs:
        get_list_observables = observables(api_url, api_token, search)

        for object_observables in get_list_observables:
            if(validators.domain(object_observables['observable_value'])):
                data_record.append(
                    {"DOMAIN": object_observables['observable_value'], "IP": ip_forward})
    data_record = convert_record_dns(data_record)
    writefile(data_record, "data/blacklist_from_ti.db")


def update_black_mirror():

    # from github
    black_mirror = requests.get(
         'https://github.com/T145/black-mirror/releases/download/latest/black_domain.txt')
    writefile(black_mirror.text,  "data/blacklist_from_mirror")
    data_record = []
    records = ""
    try:
        with open('data/blacklist_from_mirror') as f:
            lines = f.readlines()
            i = 1
            for line in lines:
                record = "IP DOMAIN\n"
                record = record.replace("DOMAIN", line.strip('\n'))
                record = record.replace("IP", ip_forward)
                records += record
                i += 1
                print(i)
                if i % 500000 == 0:
                    print("write file records")
                    print(''.join(["data/blacklist_from_mirror", str(i)]))
                    writefile(records, ''.join(["data/blacklist_from_mirror",str(i)]))
                    records = ""
        writefile(records, "data/blacklist_from_mirror")
    except e:
        print("An exception occurred". e)


def main():
    # update_record()
    update_black_mirror()

    # writefile(x.text, "data/blacklist_from_ti.db")


if __name__ == "__main__":
    main()
