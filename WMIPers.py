#!/usr/bin/env python3
# WMIPers.py
# Version 1.9.1
#
# Author:
#   Diego Perez - 2017
#
# Usage:
#   python WMIPers.py Name_of_File (Usually OBJECTS.DATA)
#
# Description:
#   Execution time varies from 5 seconds to 30 seconds.
#   This script is meant to find WMI persistence by parsing the contents
#   of OBJECTS.DATA files. It doesn't require any particular dependencies. 
#
# References: 
#	https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
#
# License:
#   Copyright (c) 2017 Diego Perez
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#

import mmap, re, sys
from collections import defaultdict

# Defining general variables	

# Precompiled objects to list all FilterToConsumerBindings
FilterToConsumerBindings = re.compile(br'\x80\x00__FilterToConsumerBinding\x00.*?(?:\:|)(\w*?EventConsumer)\.Name\=\"([\w\s]*)\".*?EventFilter\.Name\=\"([\w\s]*)\"')
    
ScriptConsumer_Pattern = re.compile(br'\x80\x00ActiveScriptEventConsumer(.{2,100})\x00\x00(VBScript|JSCript|Powershell)\x00+\W(.*?)\x00[A-Z0-9]', re.DOTALL | re.I)

EventFilter_Pattern = re.compile(br'\x80\x00__EventFilter.*?\b([a-zA-Z]\w.*?)\b\x00\x00\b(\w.*?)(?:\b\x00\x00\b(\w.*?)\x00\x00WQL|\B\x00\x00WQL)', re.I)

CommandConsumer_Pattern = re.compile(br'\x80\x00CommandLineEventConsumer\x00\x00(.*?)(?:\x00\x00|\x00.*\b)(\w.*?)\x00\x00(.*?)\x00[A-Z0-9]\x00[A-Z0-9]', re.I)

# Dictonary to contain all our findings
FilterToConsumer_dict = defaultdict(list)

# These guys are here to hold temporal values for Scripts and Filters so that we don't duplicate our output
LWMIScript = []
LWMIFilter = []
LWMICommand = []
DictFilter = []

# This function will allow us to add data to the main Dictionary after populating it with all WMI attributes
def UpdateDict(EventType, EventName, EventData):
	if EventType == "Script":
		for k, v in FilterToConsumer_dict.items():
			if v[0]["EventConsumerName"] in EventName or v[0]["EventFilterName"] in EventName:
				FilterToConsumer_dict[k][0].update({'ConsumerData':EventData})
	
	if EventType == "Filter":
		for k, v in FilterToConsumer_dict.items():
			if v[0]["EventConsumerName"] in EventName or v[0]["EventFilterName"] in EventName:
				FilterToConsumer_dict[k][0].update({'EventFilter':EventData})
	
	if EventType == "Command":
		for k, v in FilterToConsumer_dict.items():
			if v[0]["EventConsumerName"] in EventName or v[0]["EventFilterName"] in EventName:
				FilterToConsumer_dict[k][0].update({'ConsumerData':EventData[2] + EventData[1] + EventData[0]})
				
def main():
	
	file = open(sys.argv[1], 'rb', 0)
	with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
		print("\n++++++ FILE ", sys.argv[1], " ++++++")

		# Let's first create a list of dictionaries containing all Event Bindings [Consumers + Filters + data]
		for index, matches in enumerate(re.findall(FilterToConsumerBindings, s)):
			if (matches[2].decode("latin-1")) not in DictFilter:
				DictFilter.append(matches[2].decode("latin-1"))
				FilterToConsumer_dict["Binding " + str(index)].append({"FilterToConsumerType":(matches[0].decode("latin-1")), "EventFilterName":(matches[2].decode("latin-1")), "EventFilter":"", "EventConsumerName":(matches[1].decode("latin-1")), "ConsumerData":""})
		
		# Looking for All Script Event Consumers
		if re.search(ScriptConsumer_Pattern, s):
			for index, matches in enumerate(re.findall(ScriptConsumer_Pattern, s)):

                # Checking if the name of the ActiveScriptEventConsumer is not in the list of collected (i.e. iterated)
                # names, if it is, it won't print
				if matches[0].decode("latin-1") not in LWMIScript:
					LWMIScript.append(matches[0].decode("latin-1"))
					UpdateDict("Script", (matches[0].decode("latin-1")), (matches[2].decode("latin-1")))
		else:
			print("\n---> XXX Couldn't find any ActiveScriptEventConsumers XXX")
			
		# Looking for All EventFilters
		if re.search(EventFilter_Pattern, s):
			for matches in re.findall(EventFilter_Pattern, s):

                # Checking two things: a) if the name of the EventFilter is not in the list of collected (i.e. iterated)
                # names, if it is, it won't print; b) if the EventFilter indeed belongs to a
                # legitimate event subscription by weeding out everything that doesn't belong
                # to the "root" namespace.
				if "root" in matches[0].decode("latin-1"):
					if matches[1].decode("latin-1") not in LWMIFilter:
						LWMIFilter.append(matches[1].decode("latin-1"))
						UpdateDict("Filter", (matches[1].decode("latin-1")), (matches[2].decode("latin-1")))
				
				else:
					if matches[2].decode("latin-1") == "":
						LWMIFilter.append(matches[0].decode("latin-1"))
						UpdateDict("Filter", (matches[0].decode("latin-1")), (matches[1].decode("latin-1")))
						
		else:
			print("\n---> XXX Couldn't find any EventFilters XXX")

        # Looking for CommandlineEventConsumers
		if re.search(CommandConsumer_Pattern, s):
			for matches in re.findall(CommandConsumer_Pattern, s):
				if matches[1].decode("latin-1") not in LWMICommand:
					LWMICommand.append(matches[1].decode("latin-1"))
					UpdateDict("Command", (matches[1].decode("latin-1")), [(matches[0].decode("latin-1")), " ", (matches[2].decode("latin-1"))])
				
		else:
			print("\n---> XXX Couldn't find any CommandlineEventConsumers XXX")
			
		for k, v in FilterToConsumer_dict.items():
			print(
			"\n::::::::::::\n--> {0} | {1}: {2} | {3}: {4} | {5}: {6}\n {7}: {8}\n {9}:\r\n {10}\n::::::::::::\n".format(
			k,
			"FilterToConsumerType",
			v[0]["FilterToConsumerType"],
			"EventFilterName",
			v[0]["EventFilterName"],
			"EventConsumerName",
			v[0]["EventConsumerName"],
			"--> EventFilter",
			v[0]["EventFilter"],
			"--> EventConsumer",
			v[0]["ConsumerData"],))
	file.close()
	
if __name__ == "__main__":
    main()
