"""
Copyright (c) 2015, Patrick Farrell

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

import time

class Buddy:

	def __init__(self):
		self.name = ""
		self.last_heard = -1
		self.active = False
		self.ip = ""

	def getName(self):
		return self.name

	def getIPAddress(self):
		return self.ip

	def updateLastHeardTime(self):
		self.last_heard = time.time()

	def isActive(self):
		return self.active

	def setInactive(self):
		self.active = False

	def setActive(self):
		self.active = True

	def getTimeSinceHeard(self):
		timeNow = time.time()
		timeElapsed = timeNow - self.last_heard

		return timeElapsed

class BuddyList:

	# TODO: Need a thread that goes over the buddy list and checks the last heard from time to the current
	#       time and drops buddys off the list or adds them to an inactive list.

	def __init__(self):
		self.list = []
		self.buddyTimeout = 3  #seconds since we last heard from a buddy before we set them inactive

	# Any time a new buddy discovery message is received, it should pass through this function
	# to see if we already know about this buddy, add them to the buddy list, and update their last heard from time.
	def processBuddyDiscoveryMessage(self, q_message):

		return self.addBuddy(q_message)

	def addBuddy(self, buddy_q_message):
		# First check if we know about this buddy
		new_buddy_name = buddy_q_message.message
		have_buddy = self.checkForBuddy(new_buddy_name)

		new_buddy = Buddy()
		new_buddy.name = new_buddy_name
		new_buddy.ip = buddy_q_message.ip[0]

		# If we don't have this buddy in our list, add the buddy
		if have_buddy == False:
			print "Adding new buddy %s to the list" % new_buddy.name
			new_buddy.updateLastHeardTime()
			new_buddy.active = True
			self.list.append(new_buddy)
			return True
		else:
			# We already have this buddy
			# TODO: Update their last heard from time.
			buddy = self.getBuddyByName(new_buddy_name)
			buddy.updateLastHeardTime()

			# Since the buddy could have been in the list but been inactive,
			# and we have heard from them now, set them an active.
			# This should allow them to be added back to the BuddyList in the GUI.
			if buddy.isActive() == False:
				buddy.setActive()
				# Return true to indicate that we should update the GUI.
				return True

		return False

	def checkForBuddy(self, new_buddy_name):
		for index, buddy in enumerate(self.list):
			#print index, buddy.name

			# We found this buddy in our list
			if buddy.name == new_buddy_name:
				return True

		# We didn't find the buddy in the list
		return False

	def getBuddy(self, index):
		return self.list[index]

	def getBuddyByName(self, name):
		for index, buddy in enumerate(self.list):
			# We found this buddy in our list
			if buddy.name == name:
				return buddy

		# We didnt' find the buddy in the list
		return None

	def cleanup(self):

		buddyListChanged = False
		# Scan through the list and look for buddies that we haven't heard from
		# in a while.  If we haven't heard from them, set to inactive.
		for index, buddy in enumerate(self.list):

			if buddy.getTimeSinceHeard() > self.buddyTimeout:
				#print "%s is now inactive" % buddy.name
				buddy.setInactive()
				buddyListChanged = True

		return buddyListChanged

