#!/bin/bash
ip addr flush vboxnet0
ip addr add 192.168.56.1/24 dev vboxnet0
ifconfig vboxnet0:1 10.0.0.1
ifconfig vboxnet0:2 192.168.56.103

