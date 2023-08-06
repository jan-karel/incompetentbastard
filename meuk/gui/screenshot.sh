#!/bin/zsh
filename=$(date +%s).png

dir=$(pwd)

screencapture -i ${dir}/raw/screenshots/$filename &&
pbcopy <<< '\plaatje{'$filename'}{}'
