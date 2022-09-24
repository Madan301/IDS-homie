# IDS-homie

IDS-homie is a tool which would help you strengthen your IDS (intrusion detection system) (Ex: snort) in a smart way especially during the recovery stage after an attack scenario the tool takes a pcap file as its input and displays you all the packets in it by numbering it orderly, you can select a packet by entering the packet number as the tool's input the tool will automatically generate a bunch of IDS rules based on the packet you selected. The tool will also ask you if you want to add the generated rule to the IDS rules configuration file if yes enter the appropriate query stated by the tool and you will be prompted to copy paste the generated rule and it will be automatically added to your IDS.

# Usage steps

cd IDS-homie

pip3 install requirements.txt

python3 tool.py

# USE-case

This tool can be used to strengthen your cloud computing infrastructure, your personal networks. Could be very useful in a incident response stage after an unexpected cyber attack such as a malware attack, botnet, and crypto jacking attack.

# NOTE

The ssid in each rule must be different kindly alter it according to your convinience

The default path for the rule to be added is set to /etc/snort/rules/test.rules . Kindly alter it according to your system.




