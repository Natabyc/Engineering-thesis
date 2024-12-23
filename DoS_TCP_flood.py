import xml.etree.ElementTree as ET
from panos import firewall

#connect with device - type in correct credentials
fw = firewall.Firewall("10.74.1.17", "login", "password")

#defining DoS zone parameters
zone_name = "DoS_TCP_flood"
enable_synflood = 'yes'
enable_udpflood = 'no'
enable_icmpflood = 'no'
alarm_rate = '100'
activate_rate = '1000'
maximal_rate = '1500'

#creating xml structure to add DoS Zone Protection
xml_payload_zone = f'''
    <entry name="{zone_name}">
        <flood>
        <tcp-syn>
            <enable>{enable_synflood}</enable>
        <red>
            <alarm-rate>{alarm_rate}</alarm-rate>
            <activate-rate>{activate_rate}</activate-rate>
            <maximal-rate>{maximal_rate}</maximal-rate>
        </red>
        </tcp-syn>
        <udp>
        <red>
            <alarm-rate>{alarm_rate}</alarm-rate>
            <activate-rate>{activate_rate}</activate-rate>
            <maximal-rate>{maximal_rate}</maximal-rate>
        </red>
        <enable>{enable_udpflood}</enable>
        </udp>
        <icmp>
        <red>
            <alarm-rate>{alarm_rate}</alarm-rate>
            <activate-rate>{activate_rate}</activate-rate>
            <maximal-rate>{maximal_rate}</maximal-rate>
        </red>
        <enable>{enable_icmpflood}</enable>
        </icmp>
        <icmpv6>
        <red>
            <alarm-rate>{alarm_rate}</alarm-rate>
            <activate-rate>{activate_rate}</activate-rate>
            <maximal-rate>{maximal_rate}</maximal-rate>
        </red>
        <enable>{enable_icmpflood}</enable>
        </icmpv6>
        <other-ip>
        <red>
            <alarm-rate>{alarm_rate}</alarm-rate>
            <activate-rate>{activate_rate}</activate-rate>
            <maximal-rate>{maximal_rate}</maximal-rate>
        </red>
            <enable>no</enable>
        </other-ip>
        </flood>
        <scan>
        <entry name="8001">
        <action>
        <alert/>
        </action>
            <interval>2</interval>
            <threshold>100</threshold>
        </entry>
        <entry name="8002">
        <action>
        <alert/>
        </action>
            <interval>10</interval>
            <threshold>100</threshold>
        </entry>
        <entry name="8003">
        <action>
        <alert/>
        </action>
            <interval>2</interval>
            <threshold>100</threshold>
        </entry>
        </scan>
        <discard-ip-spoof>no</discard-ip-spoof>
        <discard-ip-frag>no</discard-ip-frag>
        <strict-ip-check>no</strict-ip-check>
        <discard-tcp-split-handshake>yes</discard-tcp-split-handshake>
        <discard-overlapping-tcp-segment-mismatch>yes</discard-overlapping-tcp-segment-mismatch>
    </entry>
'''
#parameters below the flood tab were not changed as it was not part of the thesis

#specify DoS Zone Protection location where the API request will apply the changes
xpath_zone = f"/config/devices/entry[@name='localhost.localdomain']/network/profiles/zone-protection-profile"

response_zone = fw.xapi.set(xpath=xpath_zone, element=xml_payload_zone)
print(response_zone)

response_str_zone = ET.tostring(response_zone, encoding="unicode")
print(" Detailed response DoS_zone XML:", response_str_zone)

#option syn-cookies needs to be configured manually via GUI, as XML does not support it
#It is crucial to add configured Zone Protection under correct Zone Protection field in the Zone tab using GUI.
