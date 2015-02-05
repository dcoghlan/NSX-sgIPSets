#
# Script to create NSX-v IP Sets from a csv file and add them as security group members
# Written by Dale Coghlan
# Date: 05 Feb 2015
# https://github.com/dcoghlan/

# ------------------------------------------------------------------------------------------------------------------	
# Set some variables. No need to change anything else after this section

# Sets a variable to save the HTTP/XML reponse so it can be parsed and displayed.
_responsefile = 'debug-sgIPSets.xml'

# Set the managed object reference
_scope = 'globalroot-0'

# Uncomment the following line to hardcode the password. This will remove the password prompt.
#_password = 'VMware1!'
#
# ------------------------------------------------------------------------------------------------------------------	

import requests
import argparse
import getpass
import logging
import csv
import xml.etree.ElementTree as ET


try:
	# Only needed to disable anoying warnings self signed certificate warnings from NSX Manager.
	import urllib3
	requests.packages.urllib3.disable_warnings()
except ImportError:
	# If you don't have urllib3 we can just hide the warnings 
	logging.captureWarnings(True)
	
parser = argparse.ArgumentParser(description="Create NSX-v IP sets from CSV file and add them to the Security Group in the csv file.")
parser.add_argument("-u", help="OPTIONAL - NSX Manager username (default: %(default)s)", metavar="user", dest="_user", nargs="?", const='admin')
parser.set_defaults(_user="admin")
parser.add_argument("-s", help="NSX Manager hostname, FQDN or IP address", metavar="nsxmgr", dest="_nsxmgr", type=str, required=True)
parser.add_argument("-i", help="Input file in csv format", metavar="inputfile", dest="_inputfile", required=True)
parser.add_argument("-d", help="Enable script debugging", dest="_debug", action="store_true")
args = parser.parse_args()

try: 
	_password
except NameError:
	_password = getpass.getpass(prompt="NSX Manager password:")
	
# Reads command line flags and saves them to variables
_user = args._user
_nsxmgr = args._nsxmgr
_inputfile = args._inputfile

# Initialise the debug file
_responsexml = open('%s' % _responsefile, 'w')
_responsexml.close()

def f_debugMode(_debugdata):
	_responsexml = open('%s' % _responsefile, 'a+')
	_responsexml.write(_debugdata)
	_responsexml.close()
	#print("Status Code = %s" % _success.status_code)
	print("API response written to %s" % _responsefile)

def get_sgid(tag):
	for sgid in _SG_root.findall('securitygroup'):
		if sgid.find('name').text == tag:
			return sgid.find('objectId').text

def get_ipsid(tag):
	for ipsid in _ipSets_root.findall('ipset'):
		if ipsid.find('name').text == tag:
			return ipsid.find('objectId').text

			

# Set the application content-type header value
_myheaders = {'Content-Type': 'application/xml'}

with open('%s' % _inputfile, 'r+') as _csvinput:
	spamreader = csv.reader(_csvinput, delimiter=',', quotechar='|')
	for row in spamreader:
		_type = (row[1])
		if _type != 'group':
			_ipsName = (row[0])
			_ipsDesc = (row[0])
			_ipsValue = (row[2])
			_ipsNetmask = (row[3])
			# Convert index 2 and index 3 from decimal netmask to a single slash notation variable
			_ipsSlash = sum([bin(int(x)).count('1') for x in _ipsNetmask.split('.')])
			if _ipsSlash == 32:
				_ipsOutput = str(_ipsValue)
			else:
				_ipsOutput = str(_ipsValue) + "/" + str(_ipsSlash)

			# Now we parse our data to the NSX API
			_myxml = '<?xml version="1.0" encoding="UTF-8" ?>'\
			'<ipset>'\
			'<objectId/>'\
			'<type>'\
			'<typeName/>'\
			'</type>'\
			'<description>' + _ipsDesc + '</description>'\
			'<name>' + _ipsName + '</name>'\
			'<revision>0</revision>'\
			'<objectTypeName/>'\
			'<value>' + _ipsOutput + '</value>'\
			'</ipset>'

			_requests_url = 'https://%s//api/2.0/services/ipset/%s' % (_nsxmgr, _scope)
			print('Creating IPset ' + _ipsName)
			_success = requests.post((_requests_url), data=_myxml, headers=_myheaders, auth=(_user, _password), verify=False)
			
			# If something goes wrong with the xml query, and we dont get a 200 status code returned,
			# enabled debug mode and exit the script.
			if int(_success.status_code) != 201:
				f_debugMode(_success.text)
			# Checks to see if debug mode is enabled
			elif args._debug:
				_ipSetObjectId = _success.text
				print ('Success creating IPset ' + _ipsName + ' - ' + _ipsOutput)
				f_debugMode(_success.text)
			else:
				_ipSetObjectId = _success.text
				print ('Success creating IPset ' + _ipsName + ' - ' + _ipsOutput)
			
		else:
			_sg = row[0]
			_ipSet = row[2]
			
			_get_SG_url = 'https://%s/api/2.0/services/securitygroup/scope/%s' % (_nsxmgr, _scope)
			_SG_reponse = requests.get((_get_SG_url), data=_myxml, headers=_myheaders, auth=(_user, _password), verify=False)
			_SG_data = _SG_reponse.content
			_SG_root = ET.fromstring(_SG_data)
			_SG_objectId = get_sgid(_sg)
			if args._debug:
				print(_sg + ' = ' + _SG_objectId)
			
			_get_ipSets_url = 'https://%s/api/2.0/services/ipset/scope/%s' % (_nsxmgr, _scope)
			_ipSets_reponse = requests.get((_get_ipSets_url), data=_myxml, headers=_myheaders, auth=(_user, _password), verify=False)
			_ipSets_data = _ipSets_reponse.content
			_ipSets_root = ET.fromstring(_ipSets_data)
			_ipSets_objectId = get_ipsid(_ipSet)
			if args._debug:
				print(_ipSet + ' = ' + _ipSets_objectId)

			
			_add_sg_member_url = 'https://%s/api/2.0/services/securitygroup/%s/members/%s' % (_nsxmgr, _SG_objectId, _ipSets_objectId)
			_add_sg_member_reponse = requests.put((_add_sg_member_url), data=_myxml, headers=_myheaders, auth=(_user, _password), verify=False)
			if _add_sg_member_reponse.status_code != 200:
				print('Error adding ' + _ipSet + ' to Security-Group ' + _sg)
				f_debugMode(_add_sg_member_reponse.text)
			else:
				print(_ipSet + ' added as member of ' +_sg)

exit()
