"""
Copyright (c) 2014, Patrick Farrell

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted,
provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL,
DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
OR PERFORMANCE OF THIS SOFTWARE.
"""

# Written by: Patrick Farrell

import json

MESSAGE_VERSION = 1
CHAT_MESSAGE_VERSION = 1

class ChatterMessage:

	def __init__(self):
		self.msgVersion = MESSAGE_VERSION
		self.msgType = ""

	@staticmethod
	def createDiscoveryMessage(user_name, host_ip):
		"""Discovery Messages are multicast messages that get sent to alert to other users
		on the network that we are present on the network and available for chat"""

		print "ChatterMessage: sendPeriodicDiscoveryMessage"
		discovery_message = {}
		discovery_message['v'] = str(MESSAGE_VERSION)
		discovery_message['name'] = user_name
		discovery_message['ip'] = host_ip

		discovery_message_json = json.dumps(discovery_message)

		return discovery_message_json

	@staticmethod
	def parseDiscoveryMessage(raw_data):

		discovery_message = json.loads(raw_data)

		return discovery_message

	@staticmethod
	def createChatMessage(userDisplayName, messageText):

		message_box = {}
		message_box['v'] = str(CHAT_MESSAGE_VERSION)
		message_box['username'] = userDisplayName
		message_box['message'] = messageText

		return message_box

	#def parseChatterMessage(self):
		"""This function determines the version and the type of the message that was sent, then parses
		the message appropriately based on which type of message it is""" 