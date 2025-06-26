#!/bin/bash

# Array of possible events and vendors
declare -a events=(
    # Fortinet examples
    "Fortinet|Fortigate|v6.0.3|00013|traffic:forward close|3|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=1545937675 src=10.1.100.11 spt=54190 deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined dst=52.53.140.235 dpt=443 deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined FTNTFGTpoluuid=c2d460aa-fe6f-51e8-9505-41b5117dfdd4 externalId=402 proto=6 act=close FTNTFGTpolicyid=1 FTNTFGTpolicytype=policy app=HTTPS FTNTFGTdstcountry=United States FTNTFGTsrccountry=Reserved FTNTFGTtrandisp=snat sourceTranslatedAddress=172.16.200.1 sourceTranslatedPort=54190 FTNTFGTappid=40568 FTNTFGTapp=HTTPS.BROWSER FTNTFGTappcat=Web.Client FTNTFGTapprisk=medium FTNTFGTapplist=g-default FTNTFGTduration=2 out=3652 in=146668 FTNTFGTsentpkt=58 FTNTFGTrcvdpkt=105 FTNTFGTutmaction=allow FTNTFGTcountapp=2"
    "Fortinet|Fortigate|v6.0.3|32002|event:system login failed|7|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0100032002 cat=event:system FTNTFGTsubtype=system FTNTFGTlevel=alert FTNTFGTvd=vdom1 FTNTFGTeventtime=1545938140 FTNTFGTlogdesc=Admin login failed FTNTFGTsn=0 duser=admin1 sproc=https(172.16.200.254) FTNTFGTmethod=https src=172.16.200.254 dst=172.16.200.1 act=login outcome=failed reason=name_invalid msg=Administrator admin1 login failed from https(172.16.200.254) because of invalid user name"
    "Fortinet|Fortigate|v6.0.3|43008|event:user authentication success|3|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0102043008 cat=event:user FTNTFGTsubtype=user FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=1545938255 FTNTFGTlogdesc=Authentication success src=10.1.100.11 dst=172.16.200.55 FTNTFGTpolicyid=1 deviceInboundInterface=port12 duser=bob FTNTFGTgroup=N/A FTNTFGTauthproto=TELNET(10.1.100.11) act=authentication outcome=success reason=N/A msg=User bob succeeded in authentication"
    "Fortinet|Fortigate|v6.0.3|08192|utm:virus infected blocked|4|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0211008192 cat=utm:virus FTNTFGTsubtype=virus FTNTFGTeventtype=infected FTNTFGTlevel=warning FTNTFGTvd=vdom1 FTNTFGTeventtime=1545938448 msg=File is infected. act=blocked app=HTTP externalId=695 src=10.1.100.11 dst=172.16.200.55 spt=44356 dpt=80 deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined FTNTFGTpolicyid=1 proto=6 deviceDirection=0 fname=eicar.com FTNTFGTquarskip=File-was-not-quarantined. FTNTFGTvirus=EICAR_TEST_FILE FTNTFGTdtype=Virus FTNTFGTref=http://www.fortinet.com/ve?vn=EICAR_TEST_FILE FTNTFGTvirusid=2172 request=http://172.16.200.55/virus/eicar.com FTNTFGTprofile=g-default duser=bob requestClientApplication=curl/7.47.0 FTNTFGTanalyticscksum=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f FTNTFGTanalyticssubmit=false FTNTFGTcrscore=50 FTNTFGTcrlevel=critical"
    "Fortinet|Fortigate|v6.0.3|13056|utm:webfilter ftgd_blk blocked|4|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0316013056 cat=utm:webfilter FTNTFGTsubtype=webfilter FTNTFGTeventtype=ftgd_blk FTNTFGTlevel=warning FTNTFGTvd=vdom1 FTNTFGTeventtime=1545938629 FTNTFGTpolicyid=1 externalId=764 duser=bob src=10.1.100.11 spt=59194 deviceInboundInterface=port12 FTNTFGTsrcintfrole=undefined dst=185.230.61.185 dpt=80 deviceOutboundInterface=port11 FTNTFGTdstintfrole=undefined proto=6 app=HTTP dhost=ambrishsriv.wixsite.com FTNTFGTprofile=g-default act=blocked FTNTFGTreqtype=direct request=/bizsquads out=96 in=0 deviceDirection=1 msg=URL belongs to a denied category in policy FTNTFGTmethod=domain FTNTFGTcat=26 requestContext=Malicious Websites FTNTFGTcrscore=60 FTNTFGTcrlevel=high"
    "Fortinet|Fortigate|v6.0.3|16384|utm:ips signature reset|7|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=0419016384 cat=utm:ips FTNTFGTsubtype=ips FTNTFGTeventtype=signature FTNTFGTlevel=alert FTNTFGTvd=vdom1 FTNTFGTeventtime=1545938887 FTNTFGTseverity=info src=172.16.200.55 FTNTFGTsrccountry=Reserved dst=10.1.100.11 deviceInboundInterface=port11 FTNTFGTsrcintfrole=undefined deviceOutboundInterface=port12 FTNTFGTdstintfrole=undefined externalId=901 act=reset proto=6 app=HTTP FTNTFGTpolicyid=1 FTNTFGTattack=Eicar.Virus.Test.File spt=80 dpt=44362 dhost=172.16.200.55 request=/virus/eicar.com deviceDirection=0 FTNTFGTattackid=29844 FTNTFGTprofile=test-ips FTNTFGTref=http://www.fortinet.com/ids/VID29844 duser=bob FTNTFGTincidentserialno=877326946 msg=file_transfer: Eicar.Virus.Test.File,"
    "Fortinet|Fortigate|v6.0.3|30258|utm:waf waf-http-constraint passthrough|4|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=1203030258 cat=utm:waf FTNTFGTsubtype=waf FTNTFGTeventtype=waf-http-constraint FTNTFGTlevel=warning FTNTFGTvd=vdom1 FTNTFGTeventtime=1545951320 FTNTFGTpolicyid=1 externalId=13614 duser=bob FTNTFGTprofile=waf_test src=10.1.100.11 spt=57304 dst=172.16.200.55 dpt=80 deviceInboundInterface=port12 FTNTFGTsrcintfrole=lan deviceOutboundInterface=port11 FTNTFGTdstintfrole=wan proto=6 app=HTTP request=http://172.16.200.55/index.html?a\=0123456789&b\=0123456789&c\=0123456789 FTNTFGTseverity=medium act=passthrough deviceDirection=0 requestClientApplication=curl/7.47.0 FTNTFGTconstraint=url-param-num FTNTFGTrawdata=Method\=GET|User-Agent\=curl/7.47.0"
    "Fortinet|Fortigate|v6.0.3|54802|dns:dns-response pass|3|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=1501054802 cat=dns:dns-response FTNTFGTsubtype=dns-response FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=1545950726 FTNTFGTpolicyid=1 externalId=13355 duser=bob src=10.1.100.11 spt=54621 deviceInboundInterface=port12 FTNTFGTsrcintfrole=lan dst=172.16.200.55 dpt=53 deviceOutboundInterface=port11 FTNTFGTdstintfrole=wan proto=17 FTNTFGTprofile=default FTNTFGTsrcmac=a2:e9:00:ec:40:01 FTNTFGTxid=5137 FTNTFGTqname=detectportal.firefox.com FTNTFGTqtype=A FTNTFGTqtypeval=1 FTNTFGTqclass=IN FTNTFGTipaddr=104.80.89.26, 104.80.89.24 msg=Domain is monitored act=pass FTNTFGTcat=52 FTNTFGTcatdesc=Information Technology"
    "Fortinet|Fortigate|v6.0.3|61002|utm:ssh ssh-command passthrough|3|deviceExternalId=FGT5HD3915800610 FTNTFGTlogid=1600061002 cat=utm:ssh FTNTFGTsubtype=ssh FTNTFGTeventtype=ssh-command FTNTFGTlevel=notice FTNTFGTvd=vdom1 FTNTFGTeventtime=1545950175 FTNTFGTpolicyid=1 externalId=12921 duser=bob FTNTFGTprofile=test-ssh src=10.1.100.11 spt=56698 dst=172.16.200.55 dpt=22 deviceInboundInterface=port12 FTNTFGTsrcintfrole=lan deviceOutboundInterface=port11 FTNTFGTdstintfrole=wan proto=6 act=passthrough FTNTFGTlogin=root FTNTFGTcommand=ls FTNTFGTseverity=low"
)

# Function to generate a random IP address
random_ip() {
    echo "$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))"
}

# Function to generate a random port number
random_port() {
    echo $((1024 + RANDOM % 64511))
}

# Function to generate a random integer
random_int() {
    echo $((RANDOM % 100000))
}

# Function to generate a random hexadecimal string
random_hex() {
    openssl rand -hex 4
}

# Function to generate a random event time in epoch format
random_eventtime() {
    echo $(( $(date +%s) - RANDOM % 100000 ))
}

# Function to generate a random protocol number
random_proto() {
    echo $((RANDOM % 255))
}

# Function to generate a random application name
random_app() {
    apps=("HTTPS" "HTTP" "SSH" "TELNET")
    echo "${apps[$RANDOM % ${#apps[@]}]}"
}

# Function to generate a random country
random_country() {
    countries=("United States" "Reserved" "Germany" "France" "Japan")
    echo "${countries[$RANDOM % ${#countries[@]}]}"
}

# Function to generate a random risk level
random_risk() {
    risks=("low" "medium" "high")
    echo "${risks[$RANDOM % ${#risks[@]}]}"
}

# Main loop to generate logs every second
while true; do
    vendor="Fortinet"
    product="Fortigate"
    version="v6.0.3"
    sig_id=$(random_int)
    name="event"
    severity=$((RANDOM % 10))

    device_external_id="FGT$(random_hex)"
    log_id=$(random_hex)
    cat="event:system"
    subtype="system"
    level="alert"
    vd="vdom1"
    event_time=$(random_eventtime)
    src_ip=$(random_ip)
    dst_ip=$(random_ip)
    src_port=$(random_port)
    dst_port=$(random_port)
    device_in_interface="port$((RANDOM % 10))"
    device_out_interface="port$((RANDOM % 10))"
    proto=$(random_proto)
    action="login"
    outcome="failed"
    reason="name_invalid"
    msg="Randomly generated log entry"

    log_message="CEF:0|$vendor|$product|$version|$sig_id|$name|$severity|deviceExternalId=$device_external_id FTNTFGTlogid=$log_id cat=$cat FTNTFGTsubtype=$subtype FTNTFGTlevel=$level FTNTFGTvd=$vd FTNTFGTeventtime=$event_time src=$src_ip spt=$src_port deviceInboundInterface=$device_in_interface FTNTFGTsrcintfrole=undefined dst=$dst_ip dpt=$dst_port deviceOutboundInterface=$device_out_interface FTNTFGTdstintfrole=undefined proto=$proto act=$action outcome=$outcome reason=$reason msg=$msg"

    # Send the log to local syslog on UDP port 514
    echo "$log_message" | nc -w 1 -u 127.0.0.1 514

    # Optional: Also log to the local syslog via logger
    logger -p local4.warn -t CEF "$log_message"

    sleep 1
done