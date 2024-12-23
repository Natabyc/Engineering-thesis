import xml.etree.ElementTree as ET
from panos import firewall

#connect with device - type in correct credentials
fw = firewall.Firewall("10.74.1.17", "login", "password")

#defining DoS Protection and DoS Profile parameters
profile_name = "DoS_slowloris" #add suffix with attack name to know which protection is enabled
policy_name = "DoS_slowloris"
enable_synflood = 'yes' #Syn flood protection was used with Slowloris protection, as this attack exploits HTTP protocol
enable_udpflood = 'no'
enable_icmpflood = 'no'
alarm_rate = '100'
activate_rate = '1'
maximal_rate = '1000'
zone_from = 'WAN'
zone_to = 'DMZ'
max_con_sessions = '100'

#creating xml structure to add DoS Protection Profile
xml_payload = f'''
<entry name="{profile_name}">
    <flood>
        <tcp-syn>
            <red>
                <alarm-rate>{alarm_rate}</alarm-rate>
                <activate-rate>{activate_rate}</activate-rate>
                <maximal-rate>{maximal_rate}</maximal-rate>
            </red>
        <enable>{enable_synflood}</enable>
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
    </flood>
        <resource>
        <sessions>
        <enabled>yes</enabled>
        <max-concurrent-limit>{max_con_sessions}</max-concurrent-limit>
        </sessions>
        </resource>
        <type>aggregate</type>  
</entry>
'''

#specify DoS Protection profile location where the API request will apply the changes
xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/dos-protection"
response = fw.xapi.set(xpath=xpath, element=xml_payload)
print(response)

response_str = ET.tostring(response, encoding="unicode")
print("Detailed response DoS_profile XML:", response_str)


#creating xml structure to add DoS Protection rule
xml_payload_policy = f""""
<entry name="{policy_name}">
    <from>
    <zone>
        <member>{zone_from}</member>
    </zone>
    </from>
    <to>
    <zone>
        <member>{zone_to}</member>
    </zone>
    </to>
    <protection>
        <aggregate>
    <profile>{profile_name}</profile>
    </aggregate>
    </protection>
    <source>
        <member>any</member>
    </source>
    <destination>
        <member>any</member>
    </destination>
    <source-user>
        <member>any</member>
    </source-user>
    <service>
        <member>any</member>
    </service>
    <action>
        <protect/>
    </action>
</entry>
 """

#specify DoS Protection rule location where the API request will apply the changes
xpath_profile = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/dos/rules"

response_profile = fw.xapi.set(xpath=xpath_profile, element=xml_payload_policy)
print(response_profile)

response_str_profile = ET.tostring(response_profile, encoding="unicode")
print("Detailed response DoS_policy XML:", response_str_profile)

#option syn-cookies needs to be configured manually via GUI, as XML does not support it
