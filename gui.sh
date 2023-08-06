#!/bin/zsh
command=$(echo 'plaatje\nlatex\ndashboard\nopdrachten\nfinding\nnotes\nshells' | /opt/homebrew/bin/dmenu-mac)

dir=$(pwd)

case "$command" in

  plaatje)
  sh ${dir}/meuk/gui/screenshot.sh
   ;;
  notes)
    open http://127.0.0.1/notes
  ;;

  finding)
    open http://127.0.0.1/verwerkt
  ;;  
  opdrachten)
   dirname=sh ${dir}/meuk/gui/commands.sh
  ;;
  latex)
   dirname=sh ${dir}/meuk/gui/latex.sh
  ;;

  shells)
   open -t ${dir}/http/payloads/shell_443.txt
  ;;

  *)
   echo "error: unknown command in gui.sh" 1>&2
   exit 1
  ;;
esac