if [ -f ~/.bashrc ]; then
   source ~/.bashrc
fi

if [ -z "$DISPLAY" ] && [ -n "$XDG_VTNR" ] && [ "$XDG_VTNR" -eq 1 ]; then
  export XAUTHORITY=/tmp/.Xauthority
  exec startx
fi
#if [[ -z $DISPLAY ]] && [[ $(tty) = /dev/tty1 ]]; then exec startx; fi
