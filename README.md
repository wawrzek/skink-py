# Slink QT PY

This is Scratch Link clone written in Python with PyQT.
The goal is to prepare a tool enabling connection between Scratch and Lego EV3 robot for Linux users.


## Links

* https://scratch.mit.edu/ev3
* https://github.com/scratchfoundation/scratch-link/tree/develop/Documentation
* https://github.com/scratux/scratux
* https://www.lego.com/cdn/cs/set/assets/blt6879b00ae6951482/LEGO_MINDSTORMS_EV3_Communication_Developer_Kit.pdf

# Experiments

The work with Claude wasn't straightforward.
It got lost with SPP connection, which forced me to work on side projects, to prove that QT does not have problems with SPP BT connections.

## Slink

Slink is the original code from Claude.

## Raw-Connection

A desktop application to send message over SPP BT connection (Classic BT)

## EV3D

The extended version of above application with buttons triggering specific EV3 actions.
