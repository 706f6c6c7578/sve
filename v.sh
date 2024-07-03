#!/bin/bash

# Usage: ./v.sh 'message@id' pubkey

# Usenet server details
server="news.mixmin.net"
port=119

msgid=$1
pubkey=$2

# Check if the Message-ID is enclosed in angle brackets
if [[ $msgid != \<*\> ]]; then
    # If not, add them
    msgid="<"$msgid">"
fi

# Use netcat to connect to the server and get the article
printf '%s\r\n' "article $msgid" quit . | nc $server $port\
| sed -e :a -e '$d;N;2,2ba' -e 'P;D' | sve v $pubkey



