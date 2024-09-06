#!/bin/bash

lsof -i | grep ncat | tr -s ' ' | awk '{print $1" " $2" " $9}'
#lsof -i | grep ncat | tr -s ' '
