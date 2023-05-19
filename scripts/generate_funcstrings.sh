#!/bin/bash
# Script to iteratively generate esil funcstrings from a given folder containing
# extract .json files
for file in /mnt/9d58c266-2eda-42a5-bee0-f140e2ccefad/phd-data/Dataset-1/clamav/*.json
do
  bin2ml nlp --path "$file" --output-path /mnt/9d58c266-2eda-42a5-bee0-f140e2ccefad/phd-data/Dataset-1/processed/esil-fstrs/ --data-type esil --format funcstring
done
