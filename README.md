# Nagios Plugins

Creating a repo for some nagios plugins I've done.

## Installation

copy scripts into nagios plugin directory


## Usage

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

Sample output:

        Cisco Stack OK - 5 Members:: 1: ready, 2: ready, 3: ready, 4: ready, 5: ready, Stack Ring is redundant

or in VSS mode:

        Cisco Stack OK - VSSwitchMode: multiNode, cvsSwitchConvertingStatus: false. VSL:: 102: UP (2/2), 103: UP (2/2). Chassis:: 2: active, up 111 days, 3:19:03, 3: standby, up 111 days, 3:19:03. 

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/wershlak/nagios_plugins.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
