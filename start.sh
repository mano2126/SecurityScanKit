#!/bin/bash
cd "$(dirname "$0")"
echo '===================================================='
echo '  SecurityScanKit v2.0'
echo '===================================================='
echo
CMD=${1:-start}
python3 launch.py $CMD
