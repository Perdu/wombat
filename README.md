# Wombat

An experimental Wi-Fi tracking system aiming at improving user awereness toward physical tracking technologies and at experimenting new privacy-preserving mechanisms.

## Links and attribution

Developed by Célestin Matte and Mathieu Cunche during Célestin Matte's PhD thesis (see link above), at INSA Lyon, in Inria's Privatics team, under a Région Rhône-Alpes's ARC7 funding.

- [White paper: Wombat: An experimental Wi-Fi tracking system](https://hal.inria.fr/hal-01679007/document)
- [Thesis: Wi-Fi Tracking: Fingerprinting Attacks and Counter-Measures](https://hal.archives-ouvertes.fr/tel-01659783/)

## Already added privacy-preserving mechanism

- User-friendly opt-out system: users can opt out of the system by joining a fake Wi-Fi network.

## System description

Wombat is a fully functional Wi-Fi tracking platform supporting three main features: collection, storage/processing, query/output. These three features are implemented through a distributed infrastructure composed of:
- **Sensor nodes**: small devices with wireless monitoring capabilities. They collect information sent on wireless channels and forward it to the server.
- **Central server**: the central entity of the system. It receives data sent by sensor nodes and then stores it in an internal data structure.  It is also in charge of answering queries related to the stored data.

To ensure communication between the sensor nodes and the server, the _Wombat_ system relies on a wired network (Ethernet). In addition, Wombat can be enriched with a _user interface_ and an _opt-out node_:
- **User interface**: a device in charge of displaying detailed information about one or several tracked devices (see figure below). The device to display can be specified manually by its MAC address or through proximity detection.
- **Opt-out node**: an element in charge of implementing an opt-out mechanism for users refusing to be tracked by the system.

The system is made to work on a dedicated network (the server includes a DHCP server). Nodes can be switched off at any time (they function in read-only mode to be crash-proof).

Architecture of the Wombat system in a demonstration configuration:
![Architecture of the Wombat system in a demonstration configuration](figures/Wombat.png?raw=true "Architecture of the Wombat system in a demonstration configuration")

Basic user interface of Wombat displaying the device’s MAC address, the list of SSIDs, as well as a mobility trace under a timeline form:
![Basic user interface of Wombat displaying the device’s MAC address, the list of SSIDs, as well as a mobility trace under a timeline form](figures/front-end.png?raw=true "Basic user interface of Wombat displaying the device’s MAC address, the list of SSIDs, as well as a mobility trace under a timeline form")

## Content

This package contains several folders:
- the server, node and optoutAP contain the files required to run wombat on the respective machines,
- the frontend folder contains various scripts which can be used to query the wombat server:
  * send_time.py is a script to send current time to the server, as required on system startup
  * draw_timeline.py is used by query_server.py to draw the timeline
  * query_server.py can be used to query the server directly. Possible queries are:
python query_server.py nodes   # to get the list of connected and fully functioning nodes
python query_server.py stats   # to get statistics about estimated number of devices seen by the system
python query_server.py stats <topology_file>   # same, but save results to a log.txt file.
                                               # <topology_file> is required to save results according to the topology of the system.
                                               # Useful when used when display_count.py
python query_server.py <mac_address>   # to get information about device of address <mac_address>
  * display_count.py is used to display a diagram of the estimated number of devices seen along time.
    Use it with query_server.py using a command like this to monitor stats:
watch -n 10 python query_server.py stats <topology_file>
  * blind_server.py is a server to display the timeline when the server is configured
    with modes blind=true and using_sensor=false
- the ansible folder contains ansible scripts to update the system in a single command.
  Running commands are indicated at the beginning of each file.
  * bootstrap.yml and setup.yml configure a fresh archlinux installation from
    scratch. See instruction inside the boostrap.yml file.
  * node.yml configures a node.
  * server.yml configures the server. Run node.yml first.
  * optout.yml configures the optout server. Run node.yml first.
  * push_server.yml updates server using latest code and config file, which is
    faster than running the whole server.yml file.
  The other server_*.yml etc. correspond to equivalent files for various use cases.
  Note that node.yml, server.yml and optout.yml can be run multiple times without problem.

The system can be run in different modes:
- blind_mode=false: the server has to be directly queried to give any information about devices.
- blind_mode=true, using_sensor=false: a Wi-Fi dongle is plugged to the server and
  detect close devices. Timelines are sent to the front-end (frontend_ip),
  which must run frontend/blind_server.py to display results
- blind_mode=true, using_sensor=true: the server has to be queried on port 4003
  using query "device seen". If a device was seen in the previous sensor_window_seconds seconds,
  its timeline is sent back.

To change system mode, update the server configuration in ansible/files/server/server_config.json
and push it to the server using push_server.yml.

# Install

**Required hardware:** the nodes and opt-out machines should all have Wi-Fi cards handling monitor mode connected to them. We tested this system on Raspberry Pi 2 and 3 with TP-LINK TL-WN722N dongles. If running with blind_mode=True, the server should also have a Wi-Fi card. All the machines must be connected using a switch on a independant network.
For instance, to run 4 nodes, a server and an optout node, you will need: 6 machines (e.g. 6 raspberry pis, and the same number of SD cards and power supplies), 6 monitor-mode-able Wi-Fi cards, one switch with enough ports, and 6 ethernet cables (+1 to connect you own machine to run front-end scripts).

The system can be easily installed on top of an existing Arch Linux install using ansibles scripts in the ansible folder.
To install each component from scratch:
- download and install an Arch Linux image on a machine.
- boot the machine and log in
- type the following commands to create a new user, change his password, and update the system:
```bash
su -
useradd -m -G wheel -s /bin/bash wombat
passwd wombat # chose a new password
pacman -Syu
```
- note the machine's IP address
- Execute the bootstrap script with ansible:
```bash
ansible-playbook -i <ip>, --ask-sudo-pass -k bootstrap.yml --extra-vars "user=wombat"
```
You now have a basic system installed. You can use the different ansible scripts in the ansible/ folder depending on what the machine is going to be: a node (node.yml), the server (run node.yml, then server.yml) or an optout server (run node.yml, then optout.yml). Read instructions at the beginning of each of these files.

The system is made to work on a dedicated network. Once installed, remove the server from any existing network as its DHCP server may disrupt it proper functioning. Once every machines are installed and configured, link them all to a common switch and you're ready to go. You can add your own machine to the switch and query the server using the frontend/query_server.py script. The server's IP address will be 172.23.0.1 and the rest of the nodes will be on the 172.23.0.1/24 network.

To configure the different modes presented in above section, edit ansible/files/server/server_config.json before install, or /etc/wombat/server_config.json on the server after install.

To have a machine configured as an automatic front-end:
- set blind_mode=True and using_sensor=False on the server
- add the machine's MAC address in ansible/files/server/dhcpd.conf (before install) or in /etc/dhcpd.conf on the server (after install) in the "yourdevice" host and restart DHCP server. The target machine should obtain the 172.23.0.3 IP address.
- on the machine, run python blind_server.py
- also, note that the server should have a functioning Wi-Fi card supporting monitor mode connected to it.
If everything works properly, a wombat picture should appear. When a phone is moved close to the server's Wi-Fi card, the wombat picture should be replaced by the user interface presented in picture above.

## Todo

- Pre-installed SD card images for raspberry 3 may be added for easier install.
