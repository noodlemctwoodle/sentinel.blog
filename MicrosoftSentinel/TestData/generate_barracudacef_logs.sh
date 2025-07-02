#!/bin/bash

# Array of possible events and vendors
declare -a events=(
    # Barracuda WAF examples
"Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4| cat=TR dvc=10.239.1.26 duser="-" in=209 out=0 suser="-" src=101.173.234.143 spt=48293 requestCookies="-" dhost=13.86.36.66 outcome=302 suid="-" requestMethod=GET app=HTTP msg=lang=en requestContext="-" dst=- dpt=9049 rt=1659523775038 request=/pma/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 dvchost=78d886bfdc-dswq7 cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=101.173.234.143 cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=9049 cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=48293 flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app18247_561194"
"Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4| cat=TR dvc=10.239.1.26 duser="-" in=217 out=0 suser="-" src=101.173.234.143 spt=48357 requestCookies="-" dhost=13.86.36.66 outcome=302 suid="-" requestMethod=GET app=HTTP msg=lang=en requestContext="-" dst=- dpt=9049 rt=1659523776075 request=/db/webadmin/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 dvchost=78d886bfdc-dswq7 cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=101.173.234.143 cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=9049 cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=48357 flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app18247_561194"
"Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4| cat=TR dvc=10.239.1.26 duser="-" in=219 out=0 suser="-" src=101.173.234.143 spt=48427 requestCookies="-" dhost=13.86.36.66 outcome=302 suid="-" requestMethod=GET app=HTTP msg=lang=en requestContext="-" dst=- dpt=9049 rt=1659523777348 request=/phpMyAdmin5.1/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 dvchost=78d886bfdc-dswq7 cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=101.173.234.143 cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=9049 cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=48427 flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app18247_561194"
"Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4| cat=TR dvc=10.239.1.26 duser="-" in=220 out=0 suser="-" src=101.173.234.143 spt=48484 requestCookies="-" dhost=13.86.36.66 outcome=302 suid="-" requestMethod=GET app=HTTP msg=lang=en requestContext="-" dst=- dpt=9049 rt=1659523778345 request=/admin/sysadmin/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 dvchost=78d886bfdc-dswq7 cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=101.173.234.143 cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=9049 cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=48484 flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app18247_561194"
"Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4| cat=TR dvc=10.239.1.26 duser="-" in=214 out=0 suser="-" src=101.173.234.143 spt=48526 requestCookies="-" dhost=13.86.36.66 outcome=302 suid="-" requestMethod=GET app=HTTP msg=lang=en requestContext="-" dst=- dpt=9049 rt=1659523779386 request=/database/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 dvchost=78d886bfdc-dswq7 cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=101.173.234.143 cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=9049 cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=48526 flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app18247_561194"
"Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4| cat=TR dvc=10.239.1.26 duser="-" in=220 out=0 suser="-" src=101.173.234.143 spt=48594 requestCookies="-" dhost=13.86.36.66 outcome=302 suid="-" requestMethod=GET app=HTTP msg=lang=en requestContext="-" dst=- dpt=9049 rt=1659523780493 request=/db/phpmyadmin4/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 dvchost=78d886bfdc-dswq7 cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=101.173.234.143 cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=9049 cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=48594 flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app18247_561194"
"Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4| cat=TR dvc=10.239.1.26 duser="-" in=221 out=0 suser="-" src=101.173.234.143 spt=48648 requestCookies="-" dhost=13.86.36.66 outcome=302 suid="-" requestMethod=GET app=HTTP msg=lang=en requestContext="-" dst=- dpt=9049 rt=1659523781577 request=/db/phpMyAdmin-3/index.php requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 dvchost=78d886bfdc-dswq7 cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=101.173.234.143 cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=9049 cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=48648 flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app18247_561194"

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
    echo $((RANDOM % 1000))
}

# Function to generate a random timestamp (milliseconds since epoch)
random_timestamp() {
    echo $(( $(date +%s%3N) - RANDOM % 100000 ))
}

# Function to generate a random request path
random_path() {
    paths=(
        "/pma/index.php"
        "/db/webadmin/index.php"
        "/phpMyAdmin5.1/index.php"
        "/admin/sysadmin/index.php"
        "/database/index.php"
        "/db/phpmyadmin4/index.php"
        "/db/phpMyAdmin-3/index.php"
    )
    echo "${paths[$RANDOM % ${#paths[@]}]}"
}

# Function to generate a random user agent
random_user_agent() {
    agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/91.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0"
    )
    echo "${agents[$RANDOM % ${#agents[@]}]}"
}

# Function to generate a random dvchost
random_dvchost() {
    echo "$(openssl rand -hex 6)-$(openssl rand -hex 3)"
}

# Main loop to generate logs every second
while true; do
    timestamp=$(date +"%b %d %H:%M:%S")
    device_ip="10.239.1.26"
    src_ip=$(random_ip)
    dst_ip=$(random_ip)
    src_port=$(random_port)
    dst_port=9049
    proxy_port=$(random_port)
    request_path=$(random_path)
    user_agent=$(random_user_agent)
    dvchost=$(random_dvchost)
    rt=$(random_timestamp)
    in_bytes=$(random_int)
    out_bytes=0

    log_message="$timestamp Barracuda CEF: 0|BarracudaNetworks|WAAS|BNWAS-1.0|WAF|WAF|4|cat=TR dvc=$device_ip duser=\"-\" in=$in_bytes out=$out_bytes suser=\"-\" src=$src_ip spt=$src_port requestCookies=\"-\" dhost=$dst_ip outcome=302 suid=\"-\" requestMethod=GET app=HTTP msg=lang=en requestContext=\"-\" dst=- dpt=$dst_port rt=$rt request=$request_path requestClientApplication=\"$user_agent\" dvchost=$dvchost cs1Label=ClientType cs1=%ct cs2Label=Protected cs2=UNPROTECTED cs3Label=ProxyIP cs3=$src_ip cs4Label=ProfileMatched cs4=DEFAULT cs6Label=WFMatched cs6=VALID cn1Label=ServicePort cn1=$dst_port cn2Label=CacheHit cn2=0 cn3Label=ProxyPort cn3=$proxy_port flexNumber1Label=ServerTime(ms) flexNumber1=0 flexNumber2Label=TimeTaken(ms) flexNumber2=0 flexString1Label=ProtocolVersion flexString1=HTTP/1.1 BarracudaWafCustomHeader1= BarracudaWafCustomHeader2= BarracudaWafCustomHeader3= BarracudaWafResponseType=INTERNAL BarracudaWafSessionID= destinationServiceName=app$(random_int)_$(random_int)"

    # Send the log to local syslog on UDP port 514
    echo "$log_message" | nc -w 1 -u 127.0.0.1 514

    # Optional: Also log to the local syslog via logger
    logger -p local4.warn -t CEF "$log_message"

    sleep 1
done