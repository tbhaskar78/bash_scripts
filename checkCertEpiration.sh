#!/bin/bash
# Modified by Bhaskar Tallamraju
# Date: 23 July 2020
#
# Feel free to use, modify and propagate as needed. 

> unreachableOrInsecure.txt
> certLessThan30Days.txt
> certMoreThan30Days.txt
input="url.txt"
while IFS= read -r line
    do
        if [ -z "$line" ]; then
            continue   # ignore if line is empty
        fi

        # 0. Extract hostname, protocol and port from the URL list read from text file
        protocol=`echo $line | awk -F: '{print $1}'` 
        temp=(${line//:/ })
        PORT=`echo ${temp[2]} | awk -F/ '{print $1}'`
        temp=`echo $line | awk -F/ '{print $3}'`
        TARGET=`echo $temp | awk -F: '{print $1}'`
        DAYS=30;

        # 1. Check if it is uses secure HTTP
        if [ $protocol == "https" ]; then
            echo "$TARGET is secure: uses HTTPS"
        else
            echo "$TARGET uses HTTP: insecure" >> unreachableOrInsecure.txt
            echo "$TARGET uses HTTP: insecure" 
        fi

        # 2. check if server is reachable
        if curl --output /dev/null --silent --head --fail "$TARGET"; then
            echo "$TARGET is reachable "
        else
            echo "$TARGET is unreachable " >> unreachableOrInsecure.txt
            echo "============" >> unreachableOrInsecure.txt
            echo "$TARGET is unreachable " 
            echo "============"
            continue   # do not continue anymore, check the next target
        fi

        # 3. check if cert is reachable, timeout after 3 secs, don't keep waiting for openssl s_client to return
        echo "checking if $TARGET:$PORT expires in less than $DAYS days";
        expirationdate=$(timeout 3  openssl s_client -servername $TARGET -connect $TARGET:$PORT </dev/null 2>/dev/null | \
                         openssl x509 -noout -dates 2>/dev/null | \
                         awk -F= '/^notAfter/ { print $2; exit }')
        expire_epoch=$(date +%s -d "$expirationdate")
        epoch_warning=$(($DAYS*86400)) #look for 30 days
        today_epoch="$(date +%s)"
        timeleft=`expr $expire_epoch - $today_epoch`

        if [[ $timeleft -le $epoch_warning ]]; then 
            echo "KO - Certificate for $TARGET expires in less than $DAYS days, on $(date -d @$expire_epoch)" ;
            echo "Cert expires for $TARGET on $(date -d @$expire_epoch '+%Y-%m-%d')" >> certLessThan30Days.txt;
            echo "============" >> certLessThan30Days.txt
        else
            echo "OK - Certificate expires on $(date -d @$expire_epoch)";
            echo "Cert expires for $TARGET on $(date -d @$expire_epoch '+%Y-%m-%d')" >> certMoreThan30Days.txt;
            echo "============" >> certMoreThan30Days.txt
        fi;

        echo "============"
    done < "$input"
