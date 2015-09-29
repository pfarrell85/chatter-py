# chatter-py
Peer-to-peer chat application

# Written by: Patrick Farrell
# Copyright 2015

This program allows users to send reliable chat messages over TCP to 
other clients that are dynamically discovered via multicast discovery messages.

The buddy list in this program is populated by multicast discovery messages.  After
a buddy has been discovered by multicast, you can click on that buddy in the buddy list
and send reliable message to the user.  The messages are sent using a TCP connection.

# Instructions to get this to run (install in this order):
  $ sudo apt-get install python-tk
  $ sudo apt-get install python-dev
  $ sudo easy_install netifaces

# To run this program:
You currently need to specify the interface that is connected to your network.
The reason for this is because the program needs to know which interface to send
the IGMP request messages to.

python Chatter.py -i eth0

