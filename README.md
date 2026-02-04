# Skink py

This is the Scratch Link clone written in Python with PyQT.
The initial goal is to make a tool enabling connection between Scratch (Scratux) and Lego EV3 robot for Linux users.

## How to run

Following installation, activate local python environment and call the `skink.py`.


## Name

I mistyped the original name (Slink - Scratch Link) in the search engine once, and learnt that Skink is a family of lizard.
Instantly, I decided that's a perfect name for an open source project, where there are plenty of animals already.

Check more in [Skink](https://en.wikipedia.org/wiki/Skink) article on Wikipedia.


## Milestones

Milestone 1 - the first version allowing to connect Scratux to EV3


# Technical notes

## Installation

At the moment the program has to be cloned from github as sources.
The list of required packages (PyQT) is saved in requirements.txt.

```
git clone https://github.com/wawrzek/skink-py.git
cd skink-py
python -m venv .
source bin/activete
pip install -r requirments.txt
```

## Start

* Load python environment (if required)
```
source bin/active
```
* Start skink
```
python skink.py
```

## Links to extra materials

* https://scratch.mit.edu/ev3 - Scratch EV3 module documentation
* https://github.com/scratchfoundation/scratch-link/tree/develop/Documentation - official Scratch Link documentation
* https://github.com/scratux/scratux - Scratux (Scratch build and package for Linux) website
* https://github.com/scratux-revived/scratux - a bit updated version of Scratux
* https://www.lego.com/cdn/cs/set/assets/blt6879b00ae6951482/LEGO_MINDSTORMS_EV3_Communication_Developer_Kit.pdf - EV3 Communication Developer Kit
* https://doc.qt.io/qtforpython-6/overviews/qtbluetooth-overview.html - Py QT Bluetooth overview
* https://github.com/kawasaki/pyscrlink - original sratch-link Linux implementation

# Experiments

The work with Claude wasn't straightforward.
It started believe that QT does not work with SPP connections.
That forced me to work on side projects, to confirm that QT does not have problems with SPP BT.
Then there were problems with sending commands.
Scratux reported connection, but there was no reaction for programs using EV3 module.
So, I started to improve visibility of all communication.

In the [experiments](experiments) folder there are a few "side" programs, created during my investigation.

## Slink

Slink is the original code from Claude.

## Raw-Connection

A desktop application to send message over SPP BT connection (Classic BT)

## EV3D

The extended version of above application with buttons triggering specific EV3 actions.

## Slink-ui

This is original Slink with a Window to better log connections.
It became the Skink Milstone 1.
