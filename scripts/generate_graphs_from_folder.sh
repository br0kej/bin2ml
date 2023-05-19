#!/bin/bash

# Script to generate networkx graphs from a collection of .json files
# with node features that are the same as the Gemini paper

for file in normal_optims/*.json
do
  bin2ml graph --path "$file" --output-path . --feature-type gemini
done
