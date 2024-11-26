we are going to make an application in python with tkinter as gui.
1. class based approach
2. uses netmiko to connect to devices
3. load in devices using csv 
4. device and device_manager classes
5. connect and connect_manager
6. can run commands and store the output of every command to  a csv per device, as in i want to run sh int | inc connected on every single one of those devices. it will outpuit a csv of all up ports on every single device. does that make sense?
7. main window will have select all deleselct all connect, when you press connect you will be promoted for ssh creds. 
8. the headers for the csv are 'hostname', 'ip','model_id' - model id is the cisco model, we should automatically detect which model this is using regex to use the correct netmiko profile