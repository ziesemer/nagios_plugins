#!/usr/bin/env python
###############################################################
#  ========================= INFO ==============================
# NAME:         check_cisco_stack.py
# AUTHOR:       Jeffrey Wolak (wershlak), Mark A. Ziesemer (ziesemer)
# WEBSITE:      https://github.com/ziesemer/wershlak-nagios_plugins
# LICENSE:      MIT
# ======================= SUMMARY ============================
# Python rewrite of check_snmp_cisco_stack.pl
#
# https://exchange.nagios.org/directory/Plugins/Hardware/Network-Gear/Cisco/Check-cisco-3750-stack-status/details
#
# It looks like the perl version wasn't maintained and had some
# bugs working with newer switch models
#
# =================== SUPPORTED DEVICES =======================
# Lab testing with:
# 3750G
# 3750X
# 3850X
# 6509
#
# !!! WARNING !!!
# See relevant bug reports before using in your environment
#
# Bug CSCsg18188 - Major
# Desc: May cause memory leak
# Effects: 12.2(25)SEE1
# Fixed: 12.2(35)SE
#
# Bug CSCse53528 - Minor
# Desc: May report the wrong status
# Effects: 12.2(25)SEE
# Fixed: 12.2(25)SEE3, 12.2(35)SE (and Later)
#
# ========================= NOTES =============================
# 2015-11-27: Version 1.0 released (Moving to PROD)
# 2015-12-04 - 1.1: Now marking all states other than "ready" as critical
# 2016-06-06 - 1.2: Add SNMP version 2 support.
#                   Return an exit status code of 3/UNKNOWN if -v / --version is used.
#                   Update standard output to show # of members,
#                   and to show members in sorted order.
#                   Allow supplying SNMP community string from keyed file.
#                   (ziesemer)
# 2016-06-07 - 1.3: Add support for Cisco VSS (Virtual Switching System) mode.
#                   (ziesemer)
# 2016-12-03 - 1.4: Fix "zero length field name in format" error on Python 2.6.
#                   (ziesemer)
# 2017-01-02 - 1.5: Add option for setting expected size range of stack ring,
#                   don't consider any stack ring status for expected 1-member stacks,
#                   and otherwise return a warning if the expected size range is not matched.
#                   Minor performance optimization for stack_state().
#                   (ziesemer)
# 2017-03-05 - 1.6: Add support for SNMPv3.
#                   Print out all provided variables on debug.
#                   Take note of deprecated command-line arguments!
#                   Minor performance optimization through use of netsnmp.Session.
#                   (ziesemer)
# 2018-06-28 - 1.7: Changes to use numeric OIDs only to isolate from issues with various MIBs being installed.
#                   - Update logging format to include log entry severity, and add additional logging.
#                   (ziesemer)
#
# ======================= LICENSE =============================
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# ###############################################################
import datetime  # for timedelta for VSS uptime.
import getopt    # for parsing options
import logging   # for debug option
import netsnmp   # Requires net-snmp compiled with python bindings
import re        # for reading key=value files.
import sys       # exit
import traceback # for error handling

# Global program variables
__program_name__ = "Cisco Stack"
__version__ = "1.6"

ciscoMgmt = ".1.3.6.1.4.1.9.9"

snmp_kwargs_defaults = None

###############################################################
#
# Exit codes and status messages
#
###############################################################
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

class RangeValueError(ValueError):
	pass

# This is NOT the same as that described at
# https://www.monitoring-plugins.org/doc/guidelines.html#THRESHOLDFORMAT ,
# but is instead closer to
# https://en.wikipedia.org/wiki/Interval_%28mathematics%29#Notations_for_intervals .
class Range:
	def __init__(self, rangeStr):
		# "Float or Integer" (from Float)
		def fi(num):
			if(num.is_integer()):
				return int(num)
			return num
		
		parts = rangeStr.split(",")
		partsLen = len(parts)
		if(partsLen == 1):
			start = end = fi(float(parts[0]))
			compare = lambda x: x == self.start
		elif(partsLen == 2):
			start = parts[0]
			if(len(start) == 0):
				raise RangeValueError("No start notation.")
			startN = start[0]
			if(startN == '['):
				startC = lambda x: self.start <= x
			elif(startN == '('):
				startC = lambda x: self.start < x
			else:
				raise RangeValueError("Unrecognized start notation: " + startN)
			start = start[1:]
			if(start == ''):
				start = float("-inf")
			else:
				start = fi(float(start))
			
			end = parts[1]
			endN = end[-1:]
			if(endN == ']'):
				endC = lambda x: x <= self.end
			elif(endN == ')'):
				endC = lambda x: x < self.end
			else:
				raise RangeValueError("Unrecognized end notation: " + endN)
			end = end[:-1]
			if(end == ''):
				end = float("inf")
			else:
				end = fi(float(end))
			
			if(start > end):
				raise RangeValueError("Invalid range (start > end): " + rangeStr)
			
			compare = lambda x: startC(x) and endC(x)
		else:
			raise RangeValueError("Invalid range: " + rangeStr)
		
		self.start = start
		self.end = end
		self.compare = compare
		self.str = rangeStr
		
	def test(self, num):
		return self.compare(num)
	
	def __repr__(self):
		return '\'' + self.str + '\''
	
def exit_status(x):
	return {
		0: "OK",
		1: "WARNING",
		2: "CRITICAL",
		3: "UNKNOWN"
	}.get(x, "UNKNOWN")


###############################################################
#
# usage() - Prints out the usage and options help
#
###############################################################
def usage():
	print("""
\t-h --help\t\t\t- Prints out this help message.
\t-v --version\t\t\t- Prints the version number.
\t-H --host <ip_address>\t\t- IP address of the Cisco stack.  Shorthand for --snmp-DestHost.
\t-m --mode <mode>\t\t- Currently "stack" (default) or "vss".
\t   --stack-size <interval>\t- Stack size to validate in math interval notation, default "[2,]".
\t   --snmp-<key> <value>\t\t- Key/value pairs of configuration values to be passed directly to the
\t\t\t\t\t  netsnmp library.  Complete reference of available options are available at
\t\thttps://net-snmp.svn.sourceforge.net/svnroot/net-snmp/trunk/net-snmp/python/README""")
	
	for k, v in sorted(snmp_kwargs_defaults.iteritems()):
		if(v == ''):
			v = '<value>'
		print("\t   --snmp-{0} {1}".format(k, v))
	
	print("""\t   --community-file <file>\t- File to read SNMP community string from.
\t   --community-key <key>\t- Key of key=value pair to read SNMP community string from in file.
\t   --auth-file <file>\t\t- File to read SNMP auth secret from.
\t   --auth-key <key>\t\t- Key of key=value pair to read SNMP auth secret from in file.
\t   --priv-file <file>\t\t- File to read SNMP priv secret from.
\t\t\t\t\t  Ommit to use the same file as --auth-file (and only read the file once).
\t   --priv-key <key>\t\t- Key of key=value pair to read SNMP priv secret from in file.
\t-d --debug\t\t\t- Verbose mode for debugging.
\t-c --community <string>\t\t- DEPRECATED: SNMP community string.
\t   --snmp-protocol-version <#>\t- DEPRECATED: SNMP protocol version.
""")
	sys.exit(UNKNOWN)

def readSecret(keyParam, fileParam, snmpParam, options, snmp_kwargs, secrets=None):
	if(options[keyParam] or options[fileParam]):
		if(options[keyParam] is None or (options[fileParam] is None and secrets is None)):
			print("Neither or both of {0} and {1} must be provided.".format(keyParam, fileParam))
			usage()
		try:
			if((secrets is None) or (options[fileParam] is not None)):
				# Based on http://stackoverflow.com/a/34518072/751158:
				ignores = re.compile("^#|\s*\r?\n")
				secrets = dict(line.strip().split("=", 1) for line in open(options[fileParam]) if not ignores.match(line))
			snmp_kwargs[snmpParam] = secrets[options[keyParam]]
			return secrets
		except:
			traceback.print_exc()
			sys.exit(UNKNOWN)

###############################################################
#
# parse_args() - parses command line args and returns options dict
#
###############################################################
def parse_args():
	global snmp_kwargs_defaults

	options = dict([
		("community-key", None),
		("community-file", None),
		("auth-key", None),
		("auth-file", None),
		("priv-key", None),
		("priv-file", None),
		("mode", "stack"),
		("stack-size", Range("[2,]"))
	])
	
	snmp_kwargs = {
		"Version": 1,
		"Community": "Public",
		# UseNumeric is required to remain agnostic to installed MIBs, etc.
		# - https://github.com/ziesemer/wershlak-nagios_plugins/issues/3
		"UseNumeric": 1
	}
	# This is a little bit of a hack to get valid options, along with default values and their types.
	snmp_kwargs_defaults = netsnmp.client._parse_session_args(snmp_kwargs)
	
	snmp_kwargs_listopts = []
	for k in snmp_kwargs_defaults.keys():
		snmp_kwargs_listopts.append("snmp-" + k + "=")
	
	try:
		opts, args = getopt.getopt(sys.argv[1:],
			"hvH:c:m:d",
			["help", "version", "host=",
				"mode=", "stack-size=", "debug",
				"community-file=", "community-key=",
				"auth-file=", "auth-key=",
				"priv-file=", "priv-key=",
				# Below line is deprecated options.
				"community=", "snmp-protocol-version="
			]
			+ snmp_kwargs_listopts)
	except getopt.GetoptError as err:
		# print help information and exit:
		print(str(err)) # will print something like "option -a not recognized"
		usage()
	for o, a in opts:
		if o in ("-h", "--help"):
			usage()
		elif o in ("-v", "--version"):
			print("{0} plugin version {1}".format(__program_name__, __version__))
			sys.exit(UNKNOWN)
		elif o in ("-H", "--host"):
			snmp_kwargs["DestHost"] = a
		elif o in ("-c", "--community"):
			# Deprecated option.
			snmp_kwargs["Community"] = a
		elif o in ("--community-file"):
			options["community-file"] = a
		elif o in ("--community-key"):
			options["community-key"] = a
		elif o in ("--auth-file"):
			options["auth-file"] = a
		elif o in ("--auth-key"):
			options["auth-key"] = a
		elif o in ("--priv-file"):
			options["priv-file"] = a
		elif o in ("--priv-key"):
			options["priv-key"] = a
		elif o in ("-m", "--mode"):
			if a not in ("stack", "vss"):
				print("Unrecognized mode: " + a)
				usage()
			options["mode"] = a
		elif o in ("--stack-size"):
			options["stack-size"] = Range(a)
		elif o in ("--snmp-protocol-version"):
			# Deprecated option.
			snmp_kwargs["Version"] = int(a)
		elif o in ("-d", "--debug"):
			logging.basicConfig(
				level = logging.DEBUG,
				format = "%(asctime)s %(levelname)s %(funcName)s - %(message)s"
			)
			logging.debug("*** Debug mode started ***")
		elif o.startswith("--snmp-"):
			o = o[7:]
			if(type(snmp_kwargs_defaults[o]) is int):
				a = int(a)
			snmp_kwargs[o] = a
			
			if(o == "UseNumeric"):
				logging.warning("This script requires that SNMP UseNumeric=1.")
		else:
			assert False, "unhandled option: " + o
	
	readSecret("community-key", "community-file", "Community", options, snmp_kwargs)
	# Use same file for reading the priv-key as the auth-key, if not otherwise specified.
	secrets = readSecret("auth-key", "auth-file", "AuthPass", options, snmp_kwargs)
	readSecret("priv-key", "priv-file", "PrivPass", options, snmp_kwargs, secrets)
	
	if(logging.getLogger().isEnabledFor(logging.DEBUG)):
		logging.debug("Printing initial options variables: {0}".format(options))
		logging.debug("Printing initial snmp_kwargs variables: {0}".format(snmp_kwargs))
	
	if("DestHost" not in snmp_kwargs):
		print("Requires host to check!")
		usage()
	
	options["snmp_kwargs"] = snmp_kwargs
	
	return options


###############################################################
#
# plugin_exit() - Prints value and exits
# :param exitcode: Numerical or constant value
# :param message: Message to print
#
###############################################################
def plugin_exit(exitcode, message=""):
	logging.debug("Exiting with status {0}. Message: {1}".format(exitcode, message))
	status = exit_status(exitcode)
	print("{0} {1} - {2}".format(__program_name__, status, message))
	sys.exit(exitcode)

def ciscoSnmpWalk(options, oidSuffix, errSuffix):
	logging.debug("Walking %s...", errSuffix)
	oid = netsnmp.VarList(netsnmp.Varbind(ciscoMgmt + oidSuffix))
	options["snmp_session"].walk(oid)
	if not oid:
		plugin_exit(CRITICAL, "Unable to retrieve SNMP " + errSuffix)
	return oid

def ciscoSnmpGet(options, oidSuffix, errSuffix):
	logging.debug("Getting %s...", errSuffix)
	vars = netsnmp.VarList(netsnmp.Varbind(ciscoMgmt + oidSuffix))
	options["snmp_session"].get(vars)
	oid = vars[0]
	if not oid:
		plugin_exit(CRITICAL, "Unable to retrieve SNMP " + errSuffix)
	return oid

###############################################################
#
# get_stack_info() - Acquire info about the stack status
# :param options: Global options dict
# :return member_table: dict of dict of stack status
#
# -- member_table example:
# {'4001': {'status': 'ready', 'index': '4001', 'number': '4', 'status_num': '4'},
#  '2001': {'status': 'ready', 'index': '2001', 'number': '2', 'status_num': '4'},
#  '3001': {'status': 'ready', 'index': '3001', 'number': '3', 'status_num': '4'},
#  '1001': {'status': 'ready', 'index': '1001', 'number': '1', 'status_num': '4'}}
#
# -- OID definitions:
# OID: 1.3.6.1.4.1.9.9.500.1.2.1.1.1
#   "This object contains the current switch identification number.
#   This number should match any logical labeling on the switch.
#   For example, a switch whose interfaces are labeled
#   'interface #3' this value should be 3."
#
# OID: 1.3.6.1.4.1.9.9.500.1.2.1.1.6
#   "The current state of a switch"
#   See stack_state() documentation for all states
#
###############################################################
def get_stack_info(options):
	member_table = {}
	
	stack_table_oid = ciscoSnmpWalk(options, ".500.1.2.1.1.1", "stack table")
	for member in stack_table_oid:
		logging.debug("member: {0}".format(member.print_str()))
		a = {"number": member.val, "index": member.iid}
		member_table[a["index"]] = a
	
	stack_status_oid = ciscoSnmpWalk(options, ".500.1.2.1.1.6", "stack status")
	for member in stack_status_oid:
		logging.debug("member: {0}".format(member.print_str()))
		index = member.iid
		member_table[index]["status_num"] = member.val
		member_table[index]["status"] = stack_state(int(member.val))
	
	logging.debug("Stack info table to return: {0}".format(member_table))
	
	return member_table


# -- STACK STATES --
#
# Defined by Cisco:
#
# http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?
#   objectInput=1.3.6.1.4.1.9.9.500.1.2.1.1.6&translate=Translate&submitValue=SUBMIT
#
# The current state of a switch:
# - waiting - Waiting for a limited time on other switches in the stack to come online.
# - progressing - Master election or mismatch checks in progress.
# - added - The switch is added to the stack.
# - ready - The switch is operational.
# - sdmMismatch - The SDM template configured on the master is not supported by the new member.
# - verMismatch - The operating system version running on the master is different from the operating
#     system version running on this member.
# - featureMismatch - Some of the features configured on the master are not supported on this member.
# - newMasterInit - Waiting for the new master to finish initialization after master switchover
#     (Master Re-Init).
# - provisioned - The switch is not an active member of the stack.
# - invalid - The switch's state machine is in an invalid state.
# - removed - The switch is removed from the stack.

def stack_state(x):
	return stackStates.get(x, "UNKNOWN")

stackStates = {
	1: "waiting",
	2: "progressing",
	3: "added",
	4: "ready",
	5: "sdmMismatch",
	6: "verMismatch",
	7: "featureMismatch",
	8: "newMasterInit",
	9: "provisioned",
	10: "invalid",
	11: "removed",
}


###############################################################
#
# get_ring_status() - Acquire info about the stack status
# :param options: Global options dict
# :return stack_ring_status: status of the stack ring
#
# OID: 1.3.6.1.4.1.9.9.500.1.1.3
#   "A value of 'true' is returned when the stackports are
#   connected in such a way that it forms a redundant ring."
#
###############################################################
def get_ring_status(options):
	ring_status_oid = ciscoSnmpGet(options, ".500.1.1.3.0", "stack ring redundancy status")
	logging.debug("Ring status: {0}".format(ring_status_oid.print_str()))
	stack_ring_status = ring_status_oid.val
	return stack_ring_status


###############################################################
#
# evaluate_results() - Evaluate status of stack and ring
# :param stack: stack info dict
# :param ring: ring status
# :param options: Global options dict
# :return result: result for exit code
# :return message: status message string for exit
#
###############################################################
def evaluate_stack_results(stack, ring, options):
	message = [str(len(stack)), " Members:: "]
	result = OK
	logging.debug("Checking each stack member...")
	for i, member in sorted(stack.iteritems()):
		logging.debug("Member {0} is {1}.".format(member["number"], member["status"]))
		message.append("{0}: {1}, ".format(member["number"], member["status"]))
		if(member["status_num"] is not "4"):
			result = CRITICAL
			logging.debug("Status changed to CRITICAL")
	
	if(ring):
		if(ring == "1"):
			message.append("Stack Ring is redundant.")
		else:
			message.append("Stack Ring is non-redundant.")
			if(result == OK):
				result = WARNING
				logging.debug("Status changed to WARNING")
	else:
		message.append("not checking stack ring.")
	
	stackSizeRange = options["stack-size"]
	if(not(stackSizeRange.test(len(stack)))):
		message.append(" Stack size NOT within range: {0}.".format(stackSizeRange.str))
		if(result == OK):
			result = WARNING
			logging.debug("Status changed to WARNING")
	
	message = "".join(message)
	return result, message

def run_stack(options):
	stack = get_stack_info(options)
	if(len(stack) > 1):
		ring = get_ring_status(options)
	else:
		ring = None
	return evaluate_stack_results(stack, ring, options)

def run_vss(options):
	warning = False
	critical = False
	unknown = False
	
	message = []
	
	cvsSwitchModeOid = ciscoSnmpGet(options, ".388.1.1.4.0", "cvsSwitchMode")
	
	message.append("VSSwitchMode: ")
	
	vssVal = cvsSwitchModeOid.val
	logging.debug("vssVal: %s", vssVal)
	try:
		vssVal = int(cvsSwitchModeOid.val)
	except ValueError:
		pass
	if(vssVal == 1):
		message.append("standalone (ERROR)")
		critical = True
	elif(vssVal == 2):
		message.append("multiNode")
	else:
		message.append("UNKNOWN ({0})".format(vssVal))
		unknown = True
	
	cvsSwitchConvertingStatusOid = ciscoSnmpGet(options, ".388.1.1.5.0", "cvsSwitchConvertingStatus")
	
	message.append(", cvsSwitchConvertingStatus: ")
	
	vssConvertVal = cvsSwitchConvertingStatusOid.val
	logging.debug("vssConvertVal: %s", vssConvertVal)
	try:
		vssConvertVal = int(vssConvertVal)
	except ValueError:
		pass
	if(vssConvertVal == 1):
		message.append("true (ERROR)")
		critical = True
	elif(vssConvertVal == 2):
		message.append("false")
	else:
		message.append("UNKNOWN ({0})".format(vssConvertVal))
		unknown = True
	
	cvsVSLConnectionEntryOid = ciscoSnmpWalk(options, ".388.1.3.1.1", "cvsVSLConnectionEntry")
	vslTab = oidToTable(cvsVSLConnectionEntryOid)
	logging.debug("vslTab: %s", vslTab)
	
	message.append(". VSL:: ")
	for link, attribs in sorted(vslTab.iteritems()):
		message.append("{:d}: ".format(link))
		status = int(attribs[3])
		if(status == 1):
			message.append("UP")
		elif(status == 2):
			message.append("down (ERROR)")
			critical = True
		else:
			message.append("UNKNOWN ({:d})".format(status))
			unknown = True
		
		linksConfigured = int(attribs[5])
		linksOperational = int(attribs[6])
		message.append(" ({:d}/{:d})".format(linksOperational, linksConfigured))
		if(linksOperational != linksConfigured):
			message.append("(WARNING)")
			warning = True
		message.append(", ")
	
	# Remove last trailing separator.
	message.pop()
	
	cvsChassisEntryOid = ciscoSnmpWalk(options, ".388.1.2.2.1", "cvsChassisEntry")
	chassisTab = oidToTable(cvsChassisEntryOid)
	logging.debug("chassisTab: %s", chassisTab)
	
	message.append(". Chassis:: ")
	chassisId = 0
	for chassis, attribs in sorted(chassisTab.iteritems()):
		message.append("{:d}: ".format(chassis))
		role = int(attribs[2])
		if(role == 1):
			message.append("standalone (ERROR)")
			critical = True
		elif(role == 2):
			message.append("active")
			if(chassisId != 0):
				message.append(" (WARNING)")
				warning = True
		elif(role == 3):
			message.append("standby")
			if(chassisId == 0):
				message.append(" (WARNING)")
				warning = True
		else:
			message.append("UNKNOWN ({:d})".format(status))
			unknown = True
		message.append(", up {:s}".format(datetime.timedelta(seconds=int(attribs[3])/100)))
		message.append(", ")
		chassisId += 1
		
	# Remove last trailing separator.
	message.pop()
	
	message.append(".")
	
	result = OK
	if(critical):
		result = CRITICAL
	elif(warning):
		result = WARNING
	elif(unknown):
		result = UNKNOWN
	message = "".join(message)
	return result, message

def oidToTable(oid):
	tab = {}
	for member in oid:
		logging.debug("member: {0}".format(member.print_str()))
		attr = int(member.tag.rsplit(".").pop())
		tab.setdefault(int(member.iid), {})[attr] = member.val
	return tab

###############################################################
#
# main() - Main function
#
###############################################################
def main():
	try:
		options = parse_args()
		
		# SNMP is almost exclusively connectionless UDP, so it's not like this will provide connection pooling.
		# However, this should save some repeated memory allocations (otherwise a new session is implicitly
		#   created for every netsnmp "static" method), validations, and help benefit from anything else
		#   that the API and any future protocol enhancements may have to offer.
		options["snmp_session"] = netsnmp.Session(**options["snmp_kwargs"])
		
		result, message = getattr(sys.modules[__name__], "run_{0}".format(options["mode"]))(options)
	except SystemExit as e:
		sys.exit(e)
	except:
		traceback.print_exc()
		sys.exit(UNKNOWN)
	plugin_exit(result, message)


if(__name__ == "__main__"):
	main()
