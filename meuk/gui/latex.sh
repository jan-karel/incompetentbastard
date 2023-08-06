dir=$(pwd)


cd "${dir}/meuk/gui/latex/"
export LC_CTYPE=UTF-8
file="$(ls -1 | /opt/homebrew/bin/dmenu-mac)"
if [ -z "$file" -o "$file" = "q" ]; then
	exit 1
fi
pbcopy < "$file"
