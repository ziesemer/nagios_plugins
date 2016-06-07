#!/usr/bin/env python
###############################################################
#  ========================= INFO ==============================
# NAME:         check_cisco_stack.py
# AUTHOR:       Jeffrey Wolak
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
# 2015-06-06 - 1.2: Add SNMP version 2 support.
#                   Return an exit status code of 3/UNKNOWN if -v / --version is used.
#                   Update standard output to show # of members,
#                   and to show members in sorted order.
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
import netsnmp   # Requires net-snmp compiled with python bindings
import sys       # exit
import getopt    # for parsing options
import logging   # for debug option

# Global program variables
__program_name__ = 'Cisco Stack'
__version__ = 1.2


###############################################################
#
# Exit codes and status messages
#
###############################################################
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3


def exit_status(x):
    return {
        0: 'OK',
        1: 'WARNING',
        2: 'CRITICAL',
        3: 'UNKNOWN'
    }.get(x, 'UNKNOWN')


###############################################################
#
# usage() - Prints out the usage and options help
#
###############################################################
def usage():
    print """
\t-h --help\t\t\t- Prints out this help message
\t-v --version\t\t\t- Prints the version number
\t-H --host <ip_address>\t\t- IP address of the cisco stack
\t-c --community <string>\t\t- SNMP community string
\t   --snmp-protocol-version <#>\t- SNMP protocol version
\t-d --debug\t\t\t- Verbose mode for debugging
"""
    sys.exit(UNKNOWN)


###############################################################
#
# parse_args() - parses command line args and returns options dict
#
###############################################################
def parse_args():
    options = dict([
        ("remote_ip", None),
        ("community", "Public"),
        ("snmp-protocol-version", 1)
    ])
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvH:c:d", ["help", "version", "host=", "community=", "snmp-protocol-version=", "debug"])
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err)    # will print something like "option -a not recognized"
        usage()
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-v", "--version"):
            print "{0} plugin version {1}".format(__program_name__, __version__)
            sys.exit(UNKNOWN)
        elif o in ("-H", "--host"):
            options['remote_ip'] = a
        elif o in ("-c", "--community"):
            options['community'] = a
        elif o in ("--snmp-protocol-version"):
            options["snmp-protocol-version"] = int(a)
        elif o in ("-d", "--debug"):
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(funcName)s - %(message)s'
            )
            logging.debug('*** Debug mode started ***')
        else:
            assert False, "unhandled option"
    logging.debug('Printing initial variables')
    logging.debug('remote_ip: {0}'.format(options['remote_ip']))
    logging.debug('community: {0}'.format(options['community']))
    logging.debug('snmp-protocol-version: {0}'.format(options['snmp-protocol-version']))
    if options['remote_ip'] is None:
        print "Requires host to check"
        usage()
    
    snmp_kwargs = {
        "DestHost" : options["remote_ip"],
        "Version" : options["snmp-protocol-version"],
        "Community" : options['community']
    }
    options["snmp_kwargs"] = snmp_kwargs
    
    return options


###############################################################
#
# plugin_exit() - Prints value and exits
# :param exitcode: Numerical or constant value
# :param message: Message to print
#
###############################################################
def plugin_exit(exitcode, message=''):
    logging.debug('Exiting with status {0}. Message: {1}'.format(exitcode, message))
    status = exit_status(exitcode)
    print '{0} {1} - {2}'.format(__program_name__, status, message)
    sys.exit(exitcode)


###############################################################
#
# get_stack_info() - Acquire info about the stack status
# :param remote_ip: IP address of the system
# :param community: SNMP read community
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
    stack_table_oid = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.4.1.9.9.500.1.2.1.1.1'))
    logging.debug('Walking stack table -- ')
    netsnmp.snmpwalk(stack_table_oid, **options["snmp_kwargs"])
    if not stack_table_oid:
        plugin_exit(CRITICAL, 'Unable to retrieve SNMP stack table')
    for member in stack_table_oid:
        logging.debug('Member info: {0}'.format(member.print_str()))
        a = {'number': member.val, 'index': member.tag.rsplit('.').pop()}
        member_table[a['index']] = a
    stack_status_oid = netsnmp.VarList(netsnmp.Varbind('.1.3.6.1.4.1.9.9.500.1.2.1.1.6'))
    logging.debug('Walking stack status -- ')
    netsnmp.snmpwalk(stack_status_oid, **options["snmp_kwargs"])
    if not stack_status_oid:
        plugin_exit(CRITICAL, 'Unable to retrieve SNMP stack status')
    for member in stack_status_oid:
        logging.debug('Member info: {0}'.format(member.print_str()))
        index = member.tag.rsplit('.').pop()
        member_table[index]['status_num'] = member.val
        member_table[index]['status'] = stack_state(member.val)
    logging.debug('Stack info table to return: {0}'.format(member_table))
    return member_table


# -- STACK STATES --
#
# Defined by Cisco:
#
# http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?
#   objectInput=1.3.6.1.4.1.9.9.500.1.2.1.1.6&translate=Translate&submitValue=SUBMIT
#
#
# "The current state of a switch:
#
# waiting - Waiting for a limited time on other
# switches in the stack to come online.
#
# progressing - Master election or mismatch checks in
# progress.
#
# added - The switch is added to the stack.
#
# ready - The switch is operational.
#
# sdmMismatch - The SDM template configured on the master
# is not supported by the new member.
#
# verMismatch - The operating system version running on the
# master is different from the operating
# system version running on this member.
#
# featureMismatch - Some of the features configured on the
# master are not supported on this member.
#
# newMasterInit - Waiting for the new master to finish
# initialization after master switchover
# (Master Re-Init).
#
# provisioned - The switch is not an active member of the
# stack.
#
# invalid - The switch's state machine is in an
# invalid state.
#
# removed - The switch is removed from the stack."

def stack_state(x):
    return {
        '1': 'waiting',
        '2': 'progressing',
        '3': 'added',
        '4': 'ready',
        '5': 'sdmMismatch',
        '6': 'verMismatch',
        '7': 'featureMismatch',
        '8': 'newMasterInit',
        '9': 'provisioned',
        '10': 'invalid',
        '11': 'removed',
    }.get(x, 'UNKNOWN')


###############################################################
#
# get_ring_status() - Acquire info about the stack status
# :param remote_ip: IP address of the system
# :param community: SNMP read community
# :return stack_ring_status: status of the stack ring
#
# OID: 1.3.6.1.4.1.9.9.500.1.1.3
#   "A value of 'true' is returned when the stackports are
#   connected in such a way that it forms a redundant ring."
#
###############################################################
def get_ring_status(options):
    ring_status_oid = netsnmp.Varbind('.1.3.6.1.4.1.9.9.500.1.1.3.0')
    logging.debug('Getting stack ring redundancy status -- ')
    netsnmp.snmpget(ring_status_oid, **options["snmp_kwargs"])
    if not ring_status_oid:
        plugin_exit(CRITICAL, 'Unable to retrieve SNMP ring status')
    logging.debug('Ring status: {0}'.format(ring_status_oid.print_str()))
    stack_ring_status = ring_status_oid.val
    return stack_ring_status


###############################################################
#
# evaluate_results() - Evaluate status of stack and ring
# :param stack: stack info dict
# :param ring: ring status
# :return result: result for exit code
# :return message: status message string for exit
#
###############################################################
def evaluate_results(stack, ring):
    message = [str(len(stack)), " Members:: "]
    result = OK
    logging.debug('Checking each stack member')
    for i, member in sorted(stack.iteritems()):
        logging.debug('Member {0} is {1}'.format(member['number'], member['status']))
        message.append("{0}: {1}, ".format(member['number'], member['status']))
        if member['status_num'] is not '4':
            result = CRITICAL
            logging.debug('Status changed to CRITICAL')
    if ring == '1':
        message.append("Stack Ring is redundant")
    else:
        message.append("Stack Ring is non-redundant")
        if result == OK:
            result = WARNING
            logging.debug('Status changed to WARNING')
    message = ''.join(message)
    return result, message


###############################################################
#
# main() - Main function
#
###############################################################
def main():
    options = parse_args()
    stack = get_stack_info(options)
    ring = get_ring_status(options)
    result, message = evaluate_results(stack, ring)
    plugin_exit(result, message)


if __name__ == "__main__":
    main()
