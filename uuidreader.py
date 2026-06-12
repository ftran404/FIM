import subprocess
import json

uuid = subprocess.run(['lsblk', '-o', 'name,uuid', '--json'], capture_output=True, check=True, text=True)

data = json.loads(uuid.stdout)
block_devices = data.get('blockdevices', [])

uuid_list = []

for device in block_devices:
    for child in device.get('children', []):
        if child.get('uuid'):
            uuid_list.append(child['uuid'])

print(uuid_list)

myUSB_uuid = '91eb673f-ca10-4c66-b803-05f63e298a68'
if myUSB_uuid in uuid_list:
    print("Special USB is plugged in. Deactivating watchdog")