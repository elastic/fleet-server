#!/bin/bash

temp_dir="docker_build_context"

rm -rf "$temp_dir"
mkdir -p "$temp_dir"

rsync -R go.work go.work.sum "$temp_dir"

find . -name 'go.mod' -o -name 'go.sum' | while read file; do
	rsync -R "$file" "$temp_dir"
done
