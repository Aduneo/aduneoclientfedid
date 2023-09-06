#!/bin/bash
echo "ok"
. ./myenv/bin/activate
echo "ok2"
# Run your main process
# aduneoclientfedid &
python -m aduneoclientfedid &
 echo "ok3"

# Prevent container from exiting
while true; do sleep 1000; done
