#!/bin/bash

# Usage: $ v '<20240701202947.4A5V43021BCW@sewer.dizum.com>' pubkey_file
# For a test save my pub key 43e6681c5cf3cdc2f9ccf975f8a01b18c5e84bf0ba00605faba9cc0f8757a117
# in a file named pubkey, without any LF or CRLF.

# Check if the correct number of arguments was passed
if [ "$#" -ne 2 ]; then
    echo "Please provide the Message-ID and the pubkey as arguments."
    exit 1
fi

# Assign the arguments to variables
message_id=$1
pubkey=$2

# Check if the Message-ID contains angle brackets
if [[ $message_id != \<*\> ]]; then
    message_id="<$message_id>"
fi

# Execute the command
printf '%s\r\n' "article $message_id" quit . | nc news.mixmin.net 119 | awk '/^220 /{h=1;next}/^.\r$/{h=0;next}/^..\r$/{print".";next}h' | sve v $pubkey
