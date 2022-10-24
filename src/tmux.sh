#!/bin/bash

cd $( dirname -- "${BASH_SOURCE[0]}" )

session="srsc-tp1"
tmux kill-session -t $session
tmux new-session -d -s $session

window=0
tmux splitw -t $session:$window -v
tmux splitw -t $session:$window.0 -h

tmux send-keys -t $session:$window.2 './player.sh'  Enter
tmux send-keys -t $session:$window.1 './box.sh'  Enter
tmux send-keys -t $session:$window.0 "./server.sh" Enter

tmux attach-session -t $session
