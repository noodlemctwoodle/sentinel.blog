#!/bin/bash

# Array of possible events and vendors
declare -a events=(
    # Barracuda WAF examples
"CEF:0|Infoblox|Data Connector|2.1.3|DNS Response|DNS Response IN HTTPS NOERROR|1|src=208.50.179.13 dst=www.googleapis.com app=DNS dvc=Sentinel-Win-Main2 cs1Label=InfobloxDNSQType cs1=HTTPS cs2Label=InfobloxB1Region cs2=us-west-1"
"CEF:0|Infoblox|Data Connector|2.1.3|DNS Response|DNS Response IN A NOERROR|1|src=208.50.179.13 dst=client.wns.windows.com app=DNS dvc=Sentinel-Win-Main2 cs1Label=InfobloxDNSQType cs1=A cs2Label=InfobloxB1Region cs2=us-west-1"
"CEF:0|Infoblox|Data Connector|2.1.3|DNS Response|DNS Response IN A NOERROR|1|src=192.168.1.90 dst=a767.dspw65.akamai.net app=DNS dvc=Sentinel-Demo-DNS+DFP+DHCP cs1Label=InfobloxB1ConnectionType cs1=dfp cs2Label=InfobloxDNSQType cs2=A"


)

Info# Function to generate a random IP address
random_ip() {
    echo "$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))"
}

# Function to generate a random domain name
random_domain() {
    domains=("www.googleapis.com" "client.wns.windows.com" "a767.dspw65.akamai.net" "ctldl.windowsupdate.com")
    echo "${domains[$RANDOM % ${#domains[@]}]}"
}

# Function to generate a random device name
random_device_name() {
    devices=("Sentinel-Win-Main2" "Sentinel-Demo-DNS+DFP+DHCP" "Sentinel-Win-Edge" "Sentinel-Win-Core")
    echo "${devices[$RANDOM % ${#devices[@]}]}"
}

# Function to generate a random Infoblox region
random_infoblox_region() {
    regions=("us-west-1" "us-east-1" "eu-central-1" "ap-southeast-1")
    echo "${regions[$RANDOM % ${#regions[@]}]}"
}

# Function to generate a random DNS query type
random_dnsq_type() {
    types=("A" "HTTPS" "CNAME" "MX")
    echo "${types[$RANDOM % ${#types[@]}]}"
}

# Function to generate a random Infoblox connection type
random_connection_type() {
    types=("dfp" "remote_client" "local_client")
    echo "${types[$RANDOM % ${#types[@]}]}"
}

# Function to generate a random severity level
random_severity() {
    echo $((RANDOM % 10))
}

# Main loop to generate logs every second
while true; do
    # Generate random values for each field
    vendor="Infoblox"
    product="Data Connector"
    version="2.1.3"
    event_class_id="DNS Response"
    name="DNS Response IN $(random_dnsq_type) NOERROR"
    severity=$(random_severity)
    src_ip=$(random_ip)
    dst_domain=$(random_domain)
    device_name=$(random_device_name)
    infoblox_region=$(random_infoblox_region)
    dnsq_type=$(random_dnsq_type)
    connection_type=$(random_connection_type)

    # Construct the CEF message
    cef_message="CEF:0|$vendor|$product|$version|$event_class_id|$name|$severity|src=$src_ip dst=$dst_domain app=DNS dvc=$device_name cs1Label=InfobloxDNSQType cs1=$dnsq_type cs2Label=InfobloxB1Region cs2=$infoblox_region cs3Label=InfobloxB1ConnectionType cs3=$connection_type"

    # Send the log to local syslog on UDP port 514
    echo "$cef_message" | nc -w 1 -u 127.0.0.1 514

    # Optional: Also log to the local syslog via logger
    logger -p local4.warn -t CEF "$cef_message"

    sleep 1
done