#!/bin/sh
# This file just a shell script

COUNT=${COUNT:-100}

salt=$(mktemp)
trap "rm -f $salt" 0

for i in `seq 0 $COUNT`;do
  openssl rand -hex $i
done  > $salt 

makepasswd --minchars 0 --maxchars $COUNT --count $COUNT | paste -d "\n" - $salt 
