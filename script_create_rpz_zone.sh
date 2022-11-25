#!/bin/bash

FILENAME=$1

while read LINE
do
DOMAINS=$LINE
echo $DOMAINS IN A 0.0.0.0  >> rpz.blocklist_domains.zone

done < $FILENAME
