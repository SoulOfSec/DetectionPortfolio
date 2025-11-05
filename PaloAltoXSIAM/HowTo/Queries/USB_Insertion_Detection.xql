/*
Description:
Detects newly mounted removable USB drives across endpoints.
MITRE: TA0009 Collection → T1052 (Exfiltration Over Removable Media)
*/

dataset = xdr_data
| filter event_type = ENUM.MOUNT and event_sub_type = ENUM.MOUNT_DRIVE_MOUNT
| alter Drive_Type = json_extract(to_json_string(action_mount_device_info),"$.storage_device_drive_type")
| filter Drive_Type = "2"
| fields agent_hostname, Drive_Letter, Device_Serial_Number

config timeframe = 30d case_sensitive = false | dataset = xdr_data | filter event_type = ENUM.MOUNT 
and event_sub_type = ENUM.MOUNT_DRIVE_MOUNT and agent_hostname = "Insert_Hostname"
| alter Drive_Type = 
json_extract(to_json_string(action_mount_device_info),"$.storage_device_drive_type"), Filesystem = 
json_extract_scalar(to_json_string(action_mount_device_info),"$.storage_device_filesystem"), 
Drive_Letter = 
json_extract_scalar(to_json_string(action_mount_device_info),"$.storage_device_mount_point"), 
Device_Serial_Number = 
json_extract_scalar(to_json_string(action_mount_device_info),"$.storage_device_serial_number")
| filter Drive_Type = "2" //2 is a removable device
| fields agent_hostname, Drive_Letter, Drive_Type, Filesystem, Device_Serial_Number, 
action_device_usb_vendor_name, action_device_usb_product_name
