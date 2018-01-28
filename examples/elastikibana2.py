#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.parser import NmapParser
from elasticsearch import Elasticsearch
from datetime import datetime
from libnmap.process import NmapProcess

def store_report(nmap_report, database, index):
    rval = True
    for nmap_host in nmap_report.hosts:
        rv = store_reportitem(nmap_host, database, index)
        if rv is False:
            print("Failed to store host {0} in "
                  "elasticsearch".format(nmap_host.address))
            rval = False

    return rval


def get_os(nmap_host):
    rval = {'vendor': 'unknown', 'product': 'unknown'}
    if nmap_host.is_up() and nmap_host.os_fingerprinted:
        cpelist = nmap_host.os.os_cpelist()
        if len(cpelist):
            mcpe = cpelist.pop()
            rval.update({'vendor': mcpe.get_vendor(),
                         'product': mcpe.get_product()})
    return rval




def store_reportitem(nmap_host, database, index):
    host_keys = ["starttime", "endtime", "address", "hostnames",
                 "ipv4", "ipv6", "mac", "status"]
    jhost = {}
    for hkey in host_keys:
        if hkey == "starttime" or hkey == "endtime":
            val = getattr(nmap_host, hkey)
            jhost[hkey] = datetime.fromtimestamp(int(val) if len(val) else 0)
        else:
            jhost[hkey] = getattr(nmap_host, hkey)

    jhost.update(get_os(nmap_host))
    for nmap_service in nmap_host.services:
        reportitems = get_item(nmap_service)

        for ritem in reportitems:
            ritem.update(jhost)
            database.index(index=index,
                           doc_type="NmapItem",
                           body=ritem)
    return jhost


def get_item(nmap_service):
    service_keys = ["port", "protocol", "state"]
    ritems = []

    # create report item for basic port scan
    jservice = {}
    for skey in service_keys:
        jservice[skey] = getattr(nmap_service, skey)
    jservice['type'] = 'port-scan'
    jservice['service'] = nmap_service.service
    jservice['service-data'] = nmap_service.banner
    ritems.append(jservice)

    # create report items from nse script output
    for nse_item in nmap_service.scripts_results:
        jnse = {}
        for skey in service_keys:
            jnse[skey] = getattr(nmap_service, skey)
        jnse['type'] = 'nse-script'
        jnse['service'] = nse_item['id']
        jnse['service-data'] = nse_item['output']
        ritems.append(jnse)

    return ritems


def mycallback(nmaptask):
    nmaptask = nmap_proc.current_task
    #if nmaptask:
        #print("Task {0} ({1}): ETC: {2} DONE: {3}%".format(nmaptask.name,nmaptask.status,nmaptask.etc,nmaptask.progress))


nmap_proc = NmapProcess(targets="192.168.56.0/24",
                        options="-n -sV -T5 -A --max-retries 1",
                        event_callback=mycallback)
nmap_proc.run()

nmap_report = NmapParser.parse_fromstring(nmap_proc.stdout)

if nmap_report:
    rep_date = datetime.fromtimestamp(int(nmap_report.started))
    index = "nmap-{0}".format(rep_date.strftime('%Y-%m-%d'))
    db = Elasticsearch([{'host': '192.168.56.101', 'port': 9200, 'send_get_body_as':'POST' } ])
    j = store_report(nmap_report, db, index)
