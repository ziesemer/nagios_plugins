# Nagios / Icinga Plugins

A fork of https://github.com/wershlak/nagios_plugins, focused on feature enhancements to the Cisco Stack plugin (which is originally a Python rewrite of [check_snmp_cisco_stack.pl](https://exchange.nagios.org/directory/Plugins/Hardware/Network-Gear/Cisco/Check-cisco-3750-stack-status/details)).

Current enhancements include:
* SNMP version 2(c) and 3 (SNMPv3) support.
* Support of all SNMP parameters, as detailed at https://net-snmp.svn.sourceforge.net/svnroot/net-snmp/trunk/net-snmp/python/README.
	* Allows for any combination of SNMPv3 parameters.
	* Provides for setting of timeouts, retries, remote port, and all other current and future parameters.
	* Only connection-related options have been tested / are supported.  Some advanced options may cause the program to behave unexpectedly.
* Support for Cisco VSS (Virtual Switching System) mode.
* Option for setting expected size range of stack ring.
* Show # of members in output, and show in sorted order.
* Supplying of secrets / passwords (community string / AuthPass / PrivPass) from a keyed file (or files) for security.
	* See https://www.netmeister.org/blog/passing-passwords.html.
* Minor performance optimizations.

Full backwards compatibility with the forked version is currently maintained.

## Installation

1. Ensure that the Python library `netsnmp` is installed.
	1. For CentOS 7, `sudo yum install net-snmp-python`.
2. Copy scripts into the Nagios/Icinga plugin directory.
	1. `check_cisco_stack.py` is all that is currently required for the Cisco Stack plugin.

## Usage

### Basic Usage

Traditional examples, INSECURE!  Uses SNMPv1, and passwords passed on the command-line.
 * See https://www.netmeister.org/blog/passing-passwords.html.

#### Insecure Cisco IOS Setup

    snmp-server community insecureCommunityString RO

#### Insecure Command-Line Examples

    $ ./check_cisco_stack.py -H switch.example.com --snmp-Community insecureCommunityString

... or slightly better (still not using SNMPv3):

    $ ./check_cisco_stack.py -H switch.example.com --community-file ~/snmp.auth --community-key switch1

Where `~/snmp.auth` is a "Java" properties file, such as:

    switch1=somePassword1
    switch2=somePassword2

#### Nagios / Icinga 1.x Configuration Samples

Create a command definition

    # 'check_cisco_stack' command definition
    define command{
      command_name    check_cisco_stack
      command_line    $USER1$/check_cisco_stack.py -H $HOSTADDRESS$ $ARG1$
    }

Define a service for the stack

    define service{
      use   generic-service   ; Inherit default values from a template
      servicegroups   <group name> ;
      host_name <stack hostname>
      service_description Cisco Stack
      check_command check_cisco_stack! -H <ip address> -c <community>
    }

### SNMPv3 Usage

#### SNMPv3 Cisco IOS Setup

(Good) Simple (strong authentication):

    snmp-server group zzz-stackview v3 auth
    snmp-server user zzz-stackmonitor zzz-stackview v3 auth sha somePassword

(Better) Add some principles of least privilege:

    ! cswSwitchInfoEntry.1
    snmp-server view zzz-stackview 1.3.6.1.4.1.9.9.500.1.2.1.1.1 included
    ! cswSwitchInfoEntry.6
    snmp-server view zzz-stackview 1.3.6.1.4.1.9.9.500.1.2.1.1.6 included
    ! cswGlobals.3
    snmp-server view zzz-stackview 1.3.6.1.4.1.9.9.500.1.1.3 included
    snmp-server group zzz-stackview v3 auth read zzz-stackview
    snmp-server user zzz-stackmonitor zzz-stackview v3 auth sha somePassword

(Best) Add privacy (encryption), replacing only the last line from above:

    snmp-server user zzz-stackmonitor zzz-stackview v3 auth sha someAuthPassword priv aes 128 somePrivPassword

Note that only "AES" (default 128, not 192 or 256) and "DES" (not 3DES) are supported.  See http://www.net-snmp.org/wiki/index.php/Strong_Authentication_or_Encryption.

#### Secure Command-Line Examples

authNoPriv:

    $ ./check_cisco_stack.py -H switch.example.com --snmp-Version 3 \
      --snmp-SecName zzz-stackmonitor --snmp-SecLevel 'authNoPriv' \
      --snmp-AuthProto SHA --auth-file ~/snmp.auth --auth-key switch1

authPriv:

    $ ./check_cisco_stack.py -H switch.example.com --snmp-Version 3 \
      --snmp-SecName zzz-stackmonitor --snmp-SecLevel 'authPriv' \
      --snmp-AuthProto SHA --auth-file ~/snmp.auth --auth-key switch1-auth \
      --snmp-PrivProto AES --priv-key switch1-priv

### Sample Outputs

    Cisco Stack OK - 5 Members:: 1: ready, 2: ready, 3: ready, 4: ready, 5: ready, Stack Ring is redundant

or in VSS mode:

    Cisco Stack OK - VSSwitchMode: multiNode, cvsSwitchConvertingStatus: false. VSL:: 102: UP (2/2), 103: UP (2/2). Chassis:: 2: active, up 111 days, 3:19:03, 3: standby, up 111 days, 3:19:03.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ziesemer/wershlak-nagios_plugins.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
