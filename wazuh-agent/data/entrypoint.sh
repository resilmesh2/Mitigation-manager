#!/bin/bash
apt-get update && \
apt-get install vim -y && \
apt-get install python-is-python3 -y && \
apt-get install python3 -y && \
apt install python-all -y && \
apt-get install pip -y && \
apt-get install netcat -y && \
apt-get install curl gpg -y && \
apt-get install ncat -y && \
apt-get install lsof -y && \
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg && \
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list && \
apt-get update && \
WAZUH_MANAGER="172.26.0.3" apt-get install wazuh-agent=4.7.2-1 -y && \
#apt-get install systemd -y && \
#systemctl daemon-reload && \
#systemctl enable wazuh-agent && \
#systemctl start wazuh-agent && \
#service wazuh-agent enable
/etc/init.d/wazuh-agent start && \
echo "wazuh-agent hold" | dpkg --set-selections && \
pip install -r /var/ossec/OpenC2_Actuator/codegen_server/requirements.txt && \
#python -m /var/ossec/OpenC2_Actuator/codegen_server/openapi_server
tail -F /dev/null
