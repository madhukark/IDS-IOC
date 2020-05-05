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
nsx_pass = 'VMware1!VMware1!'

vc_ip = "10.114.200.6"
vc_user = "administrator@madhu.local"
vc_pass = "VMware1!"


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


base_url = "https://" + nsx_ip + "/api/v1/intrusion-services/affected-vms"
mydata = '{ "filters": [ { "field_names": "signature_detail.signature_id", "value": "(2010937)" } ] }'
json_object = json.loads(mydata)
json_formatted_str = json.dumps(json_object, indent=2)

try:
    response = requests.post (base_url, verify=False, auth=(nsx_user, nsx_pass), \
                              data=mydata, headers={'Content-Type': 'application/json'})
    response.raise_for_status()
except HTTPError as http_err:
    print(f'HTTP error occurred: {http_err}')  # Python 3.6
except Exception as err:
    print(f'Other error occurred: {err}')  # Python 3.6


nsx_content = response.json()

# Connect to vSphere

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

    print ("Taking a snapshot of VM: %s ..." % vm_name)
    WaitForTask(vm.CreateSnapshot( "vm_name" + "_IDS_snapshot", "Snapshot by NSX IDS", False, False))

    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        # using time.sleep we just wait until the power off action
        # is complete. Nothing fancy here.
        print ("Powering off VM: %s ..." % vm_name)
        WaitForTask(vm.PowerOff())
