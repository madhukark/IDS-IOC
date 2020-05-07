#!/usr/bin/python

import sys
import ssl
import json
import atexit
import requests

from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
from pyVmomi import vim, vmodl
from pyVim.task import WaitForTask
from pyVim import connect
from pyVim.connect import Disconnect, SmartConnect, GetSi

requests.packages.urllib3.disable_warnings()

nsx_ip = "10.114.222.72"
nsx_user = "admin"
nsx_pass = 'myPassword!myPassword!'

vc_ip = "10.114.200.6"
vc_user = "administrator@vsphere.local"
vc_pass = "myPassword!"

nsx_tag = "IDS-IOC"
nsx_scope = "isolate"

def get_obj(content, vimtype, name):
    """
     Get the vsphere object associated with a given text name
    """
    obj = None
    container = content.viewManager.CreateContainerView(
        content.rootFolder, vimtype, True)
    for c in container.view:
        if c.name == name:
            obj = c
            break
    return obj


def get(url):
    response = None
    try:
      response = requests.get (url, verify=False, auth=(nsx_user, nsx_pass))
      response.raise_for_status()
    except HTTPError as http_err:
        print ('HTTP error occured: %s' % http_err)
        sys.exit(2)
    except Exception as err:
        print ('Unknown error occured: %s' % err)
        sys.exit(2)
    return response


def post(url, mydata):
    response = None
    try:
        response = requests.post (base_url, verify=False, auth=(nsx_user, nsx_pass), \
                              data=mydata, headers={'Content-Type': 'application/json'})
        response.raise_for_status()
    except HTTPError as http_err:
        print ('HTTP error occurred: %s' % http_err)
        sys.exit(2)
    except Exception as err:
        print ('Unknown error occurred: %s' % http_err)
        sys.exit(2)
    return response


# Get all VMs and its external_id and save
base_url = "https://" + nsx_ip + "/api/v1/fabric/virtual-machines"
response = get(base_url)
vm_content = response.json()
vm_dict = {}
vm_list = []
for result in vm_content['results']:
    vm_dict[result['display_name']] = result['external_id']
    vm_list.append(result['display_name'])

# Retrieved affected VMs and process
base_url = "https://" + nsx_ip + "/api/v1/intrusion-services/affected-vms"
mydata = '{ "filters": [ { "field_names": "signature_detail.signature_id", "value": "(2010937)" } ] }'
json_object = json.loads(mydata)
json_formatted_str = json.dumps(json_object, indent=2)
response = post(base_url, mydata)
nsx_content = response.json()

si = None
context = context = ssl._create_unverified_context()
si = connect.Connect(vc_ip, 443, vc_user, vc_pass, sslContext=context)
atexit.register(Disconnect, si)

content = si.RetrieveContent()

for vm_name in nsx_content['results']:
    vm = get_obj (content, [vim.VirtualMachine], vm_name)

    if not vm:
        print ("Virtual Machine %s doesn't exists" % vm_name)
        sys.exit()

    # Add tag to the VM
    print ("Adding NSX Tag to VM: %s ..." % vm_name)
    if (vm_name in vm_list):
        base_url = "https://" + nsx_ip + "/api/v1/fabric/virtual-machines?action=add_tags"
        mydata = '{ "external_id": "' + vm_dict[vm_name] + '", \
                     "tags": [ \
                       { "tag": "' + nsx_tag + '", "scope": "' + nsx_scope + '" } \
                     ] } '
        json_object = json.loads(mydata)
        json_formatted_str = json.dumps(json_object, indent=2)
        post (base_url, mydata)

    print ("Taking a snapshot of VM: %s ..." % vm_name)
    WaitForTask(vm.CreateSnapshot( "vm_name" + "_IDS_snapshot", "Snapshot by NSX IDS", False, False))

    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        print ("Powering off VM: %s ..." % vm_name)
        WaitForTask(vm.PowerOff())
