#!/bin/bash

# based off the following two scripts
# http://www.theunsupported.com/2012/07/block-malicious-ip-addresses/
# http://www.cyberciti.biz/tips/block-spamming-scanning-with-iptables.html

# path to iptables
IPTABLES="/sbin/iptables";

# list of known spammers
URL="www.spamhaus.org/drop/drop.lasso";

# save local copy here
FILE="/tmp/drop.lasso";

# iptables custom chain
CHAIN="Spamhaus";

# check to see if the chain already exists
$IPTABLES -L $CHAIN -n

# check to see if the chain already exists
if [ $? -eq 0 ]; then

    # flush the old rules
    $IPTABLES -F $CHAIN

    echo "Flushed old rules. Applying updated Spamhaus list...."    

else

    # create a new chain set
    $IPTABLES -N $CHAIN

    # tie chain to input rules so it runs
    $IPTABLES -A INPUT -j $CHAIN

    # don't allow this traffic through
    $IPTABLES -A FORWARD -j $CHAIN

    echo "Chain not detected. Creating new chain and adding Spamhaus list...."

fi;

# get a copy of the spam list
wget -qc $URL -O $FILE

# iterate through all known spamming hosts
for IP in $( cat $FILE | egrep -v '^;' | awk '{ print $1}' ); do

    # add the ip address log rule to the chain
    $IPTABLES -A $CHAIN -p 0 -s $IP -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10

    # add the ip address to the chain
    $IPTABLES -A $CHAIN -p 0 -s $IP -j DROP

    echo $IP

done

##################################################
# DO NOT MODIFY
# Custom IP Bans for regular offenders
##################################################
$IPTABLES -A $CHAIN -p 0 -s '93.115.27.41/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '93.115.27.41/16'  -j DROP
echo '93.115.27.41/16'
$IPTABLES -A $CHAIN -p 0 -s '185.40.4.250/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '185.40.4.250/16'  -j DROP
echo '185.40.4.250/16'
$IPTABLES -A $CHAIN -p 0 -s '93.115.28.89/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '93.115.28.89/16'  -j DROP
echo '93.115.28.8/169'
$IPTABLES -A $CHAIN -p 0 -s '94.23.0.210/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '94.23.0.210/16'  -j DROP
echo '94.23.0.210/16'
$IPTABLES -A $CHAIN -p 0 -s '173.212.201.20/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '173.212.201.20/16'  -j DROP
echo '173.212.201.20'
$IPTABLES -A $CHAIN -p 0 -s '119.9.134.33/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '119.9.134.33/16'  -j DROP
echo '119.9.134.33/16'
$IPTABLES -A $CHAIN -p 0 -s '195.154.172.203/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '195.154.172.203/16'  -j DROP
echo '195.154.172.203/16'
$IPTABLES -A $CHAIN -p 0 -s '163.172.206.85/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '163.172.206.85/16'  -j DROP
echo '163.172.206.85/16'
$IPTABLES -A $CHAIN -p 0 -s '209.126.120.187/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '209.126.120.187/16'  -j DROP
echo '209.126.120.187'
$IPTABLES -A $CHAIN -p 0 -s '192.99.39.107/16' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '192.99.39.107/16'  -j DROP
echo '192.99.39.107'
$IPTABLES -A $CHAIN -p 0 -s '104.154.224.4' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '104.154.224.4'  -j DROP
echo '104.154.224.4'
$IPTABLES -A $CHAIN -p 0 -s '193.111.141.199' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '193.111.141.199'  -j DROP
echo '193.111.141.199'
$IPTABLES -A $CHAIN -p 0 -s '85.114.128.132' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '85.114.128.132'  -j DROP
echo '85.114.128.132'
$IPTABLES -A $CHAIN -p 0 -s '212.83.186.32' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '212.83.186.32'  -j DROP
echo '212.83.186.32'
$IPTABLES -A $CHAIN -p 0 -s '62.210.181.125' -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '62.210.181.125'  -j DROP
echo '62.210.181.125'
$IPTABLES -A $CHAIN -p 0 -s '104.232.37.29' -j LOG --log-prefix "[SPAMMERS]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '104.232.37.29' -j DROP
echo '104.232.37.29'
$IPTABLES -A $CHAIN -p 0 -s '85.114.112.145' -j LOG --log-prefix "[SPAMMERS]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '85.114.112.145' -j DROP
echo '85.114.112.145'

$IPTABLES -A $CHAIN -p 0 -s '68.64.174.78' -j LOG --log-prefix "[SPAMMERS]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '68.64.174.78' -j DROP
echo '68.64.174.78'

$IPTABLES -A $CHAIN -p 0 -s '155.94.65.188' -j LOG --log-prefix "[SPAMMERS]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '155.94.65.188' -j DROP
echo '155.94.65.188'

$IPTABLES -A $CHAIN -p 0 -s '42.111.205.113' -j LOG --log-prefix "[SPAMMERS]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '42.111.205.113' -j DROP
echo '42.111.205.113'

$IPTABLES -A $CHAIN -p 0 -s '103.68.17.75' -j LOG --log-prefix "[SPAMMERS]" -m limit --limit 3/min --limit-burst 10
$IPTABLES -A $CHAIN -p 0 -s '103.68.17.75' -j DROP
echo '103.68.17.75'

echo "Done!"

# remove the spam list
unlink $FILE
