# Wombat

An experimental Wi-Fi tracking system aiming at improving user awereness toward physical tracking technologies and at experimenting new privacy-preserving mechanisms.

## Links

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

The system comports several modes:
- blind_mode=false: the server has to be directly queried to give any information about devices.
- blind_mode=true, using_sensor=false: a Wi-Fi dongle is plugged to the server and
  detect close devices. Timelines are sent to the front-end (frontend_ip),
  which must run frontend/blind_server.py to display results
- blind_mode=true, using_sensor=true: the server has to be queried on port 4003
  using query "device seen". If a device was seen in the previous sensor_window_seconds seconds,
  its timeline is sent back.

To change system mode, update the server configuration in ansible/files/server/server_config.json
and push it to the server using push_server.yml.
