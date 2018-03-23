To install:
- copy node_config.json to /etc/wombat/node_config.json and edit it with your configuration

If you want to create a systemd unit (to launch script on startup):
- copy sniffer.service to /etc/systemd/system/
- sudo systemctl enable sniffer.service
