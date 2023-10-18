#!/bin/sh

# DataFile AllowedSignersFile SignerIdentity Namespace 
ssh-keygen -Y verify -f "$2" -I "$3" -n "$4" -s "$5" < "$1"
