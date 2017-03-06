import argparse

# to set up tab completition for argparse,
# open your ~/.bashrc file and add the line
# eval "$(/path/to/register-python-argcomplete haas)"
# under the user commands section
# make sure to add the path specified in your virtual
# environment if you are using one
# usually the shell script is located in path/to/venv/bin/
# then restart an interactive bash shell with
# bash
# check that the bash completition file has been
# generated with
# complete -p | grep "argcomplete"
# if so, then you're set!


class CommandFramework(object):
    """creates the skeleton of the argparse parser to
    allow faster tab completition"""

    def __init__(self):

        parser = argparse.ArgumentParser(usage='haas')
        subcommand_parsers = parser.add_subparsers()

        # Startup Commands
        serve_parser = subcommand_parsers.add_parser('serve', help="todo")
        serve_parser.add_argument('port', type=int, help="2")

        serve_networks_parser = subcommand_parsers.add_parser(
                                'serveNetworks', help="1")

        create_first_admin = subcommand_parsers.add_parser('admin')
        create_first_admin.add_argument('name')
        create_first_admin.add_argument('password')

        # PARENT PARSERS: shared options
        get_name = argparse.ArgumentParser(add_help=False)
        get_name.add_argument('name', metavar='<object name>')

        get_type = argparse.ArgumentParser(add_help=False)
        get_type.add_argument('type', metavar='<object type>')

        # parser commands by object
        node_parser = subcommand_parsers.add_parser('node')
        node_subparsers = node_parser.add_subparsers()
        network_parser = subcommand_parsers.add_parser('network')
        network_subparsers = network_parser.add_subparsers()
        user_parser = subcommand_parsers.add_parser('user')
        user_subparsers = user_parser.add_subparsers()
        project_parser = subcommand_parsers.add_parser('project')
        project_subparsers = project_parser.add_subparsers()
        switch_parser = subcommand_parsers.add_parser('switch')
        switch_subparsers = switch_parser.add_subparsers()
        headnode_parser = subcommand_parsers.add_parser('headnode')
        headnode_subparsers = headnode_parser.add_subparsers()
        nic_parser = subcommand_parsers.add_parser('nic')
        nic_subparsers = nic_parser.add_subparsers()
        hnic_parser = subcommand_parsers.add_parser('hnic')
        hnic_subparsers = hnic_parser.add_subparsers()
        port_parser = subcommand_parsers.add_parser('port')
        port_subparsers = port_parser.add_subparsers()

        node_reg_parser = node_subparsers.add_parser(
                               'register', parents=[get_name])
        node_register_subtype = node_reg_parser.add_mutually_exclusive_group(
                                required=True)
        node_register_subtype.add_argument('--mock', nargs=3,
                                           metavar=('host',
                                                    'user',
                                                    'password'))
        node_register_subtype.add_argument('--ipmi', nargs=3,
                                           metavar=('host',
                                                    'user',
                                                    'password'))

        node_delete_parser = node_subparsers.add_parser(
                             'delete', parents=[get_name])

        node_disconnect = node_subparsers.add_parser(
                          'disconnect', parents=[get_name])
        node_disconnects = node_disconnect.add_mutually_exclusive_group(
                           required=True)
        node_disconnects.add_argument('--network',
                                      nargs=2,
                                      metavar=('<network name>', '<nic name>')
                                      )
        node_disconnects.add_argument('--project', metavar='<project name>')

        node_connect = node_subparsers.add_parser(
                       'connect', parents=[get_name])
        node_connects = node_connect.add_mutually_exclusive_group(
                        required=True)
        node_connects.add_argument('--network',
                                   nargs=3,
                                   metavar=('<network name>',
                                            '<nic name>',
                                            '<channel>'))
        node_connects.add_argument('--project', metavar='<project name>')

        node_show = node_subparsers.add_parser('show', parents=[get_name])

        node_list = node_subparsers.add_parser('list')
        node_lists = node_list.add_mutually_exclusive_group(required=True)
        node_lists.add_argument('--project', '--proj')
        node_lists.add_argument('--network', '--net', nargs=2,
                                metavar=('<network name>',
                                         '<project name> or all'))
        node_lists.add_argument('--free', dest='is_free', action='store_true')
        node_lists.add_argument('--all', dest='is_free', action='store_false')

        node_console = node_subparsers.add_parser('console')
        node_console_actions = node_console.add_subparsers()
        node_console_show = node_console_actions.add_parser(
                            'show', parents=[get_name])
        node_console_start = node_console_actions.add_parser(
                             'start', parents=[get_name])
        node_console_stop = node_console_actions.add_parser(
                            'stop', parents=[get_name])

        node_power = node_subparsers.add_parser('power')
        node_powers = node_power.add_subparsers()
        node_powers_off = node_powers.add_parser('off', parents=[get_name])
        node_powers_cycle = node_powers.add_parser(
                            'cycle', parents=[get_name])

        # headnode statements
        hn_reg = headnode_subparsers.add_parser('register',
                                                parents=[get_name])
        hn_reg.add_argument('--project', '--proj', required=True)
        hn_reg.add_argument('--image', '--img',
                            choices=['img1', 'img2', 'img3', 'img4'],
                            required=True)

        # not able to look at extensions right now
        hn_delete = headnode_subparsers.add_parser('delete',
                                                   parents=[get_name])

        hn_connect = headnode_subparsers.add_parser('connect',
                                                    parents=[get_name])
        hn_connect.add_argument('--network', required=True)
        hn_connect.add_argument('--hnic', required=True)

        hn_detach = headnode_subparsers.add_parser('disconnect',
                                                   parents=[get_name])
        hn_detach.add_argument('---hnic', required=True)

        hn_start = headnode_subparsers.add_parser('start', parents=[get_name])

        hn_stop = headnode_subparsers.add_parser('stop', parents=[get_name])

        show_hn = headnode_subparsers.add_parser('show', parents=[get_name])

        list_hn = headnode_subparsers.add_parser('list')
        list_hn.add_argument('--project', '-proj', required=True)

        hn_images = headnode_subparsers.add_parser('images')

        # nic statements
        nic_register = nic_subparsers.add_parser(
            'register', parents=[get_name])
        nic_register.add_argument('--node', required=True)
        nic_register.add_argument('--macaddr', required=True)

        nic_delete = nic_subparsers.add_parser('delete', parents=[get_name])
        nic_delete.add_argument('--node', required=True)

        nic_connect = nic_subparsers.add_parser('connect', parents=[get_name])
        nic_connect.add_argument('--node', required=True)
        nic_connect.add_argument('--switch', required=True)
        nic_connect.add_argument('--port', required=True)

        nic_disconnect = nic_subparsers.add_parser('disconnect')
        nic_disconnect.add_argument('--port')
        nic_disconnect.add_argument('--switch')

        # hnic statements
        hnic_register = hnic_subparsers.add_parser(
                        'register', parents=[get_name])
        hnic_register.add_argument('--headnode', required=True)

        hnic_delete = hnic_subparsers.add_parser('delete', parents=[get_name])
        hnic_delete.add_argument('--headnode', required=True)

        # port parsers
        port_register_parser = port_subparsers.add_parser(
                               'register', parents=[get_name])
        port_register_parser.add_argument('--switch', required=True)

        port_delete_parser = port_subparsers.add_parser('delete',
                                                        parents=[get_name])
        port_delete_parser.add_argument('--switch', required=True)

        port_disconnect = port_subparsers.add_parser('disconnect',
                                                     parents=[get_name])
        port_disconnect.add_argument('--switch', required=True)

        port_connect = port_subparsers.add_parser(
                       'connect', parents=[get_name])
        port_connect.add_argument('--switch', required=True)
        port_connect.add_argument('--node', required=True)
        port_connect.add_argument('--nic', required=True)

        # network statements
        net_create = network_subparsers.add_parser(
                     'register', parents=[get_name])
        net_creates = net_create.add_mutually_exclusive_group(required=True)
        net_creates.add_argument('--description', nargs=3,
                                 metavar=('<owner>', '<access>', '<net id>'))
        net_creates.add_argument('--simple', metavar='<project name>',
                                 dest='project')

        net_delete = network_subparsers.add_parser('delete',
                                                   parents=[get_name])

        net_show = network_subparsers.add_parser('show', parents=[get_name])

        net_list = network_subparsers.add_parser('list')
        net_lists = net_list.add_mutually_exclusive_group()
        net_lists.add_argument('--project', '--proj')
        net_lists.add_argument('--attachments', nargs=2,
                               metavar=('<project name> or all',
                                        '<network name>'))

        net_connect = network_subparsers.add_parser('connect',
                                                    parents=[get_name])
        net_connects = net_connect.add_mutually_exclusive_group(required=True)
        net_connects.add_argument('--headnode', '--hnode', nargs=2,
                                  metavar=('<headnode name>', '<hnic name>'))
        net_connects.add_argument('--node', nargs=3,
                                  metavar=('<node name>',
                                           '<nic name>',
                                           '<channel>'))
        net_connects.add_argument('--project', '--proj')

        net_dis = network_subparsers.add_parser('disconnect',
                                                parents=[get_name])
        net_disconnects = net_dis.add_mutually_exclusive_group(required=True)
        net_disconnects.add_argument('--project', '--proj')
        net_disconnects.add_argument('--headnode', '--hnode', nargs=2,
                                     metavar=('<headnode name>',
                                              '<hnic name>'))
        net_disconnects.add_argument('--node', nargs=2,
                                     metavar=('<node name>', '<nic name>'))

        # project parser
        proj_create = project_subparsers.add_parser('register',
                                                    parents=[get_name])

        proj_delete = project_subparsers.add_parser('delete',
                                                    parents=[get_name])

        proj_connect = project_subparsers.add_parser('connect',
                                                     parents=[get_name])
        proj_connect.add_argument('--node')
        proj_connect.add_argument('--network', '--net')
        proj_connect.add_argument('--user')

        proj_dis = project_subparsers.add_parser('disconnect',
                                                 parents=[get_name])
        proj_dis.add_argument('--user')

        proj_dis.add_argument('--network', '--net')
        proj_dis.add_argument('--node')

        proj_list = project_subparsers.add_parser('list')

        # switch parser
        switch_register_parser = switch_subparsers.add_parser(
                                 'register', parents=[get_name])
        switch_registers = switch_register_parser.add_mutually_exclusive_group(
                           required=True)
        switch_registers.add_argument('--nexus', nargs=4,
                                      metavar=('host', 'user',
                                               'password', 'vlan'))
        switch_registers.add_argument('--mock', nargs=3,
                                      metavar=('host', 'user', 'password'))
        switch_registers.add_argument('--powerconnect55xx', nargs=3,
                                      metavar=('host', 'user', 'password'))
        switch_registers.add_argument('--brocade', nargs=4,
                                      metavar=('host', 'user',
                                               'pwd', 'interface'))

        switch_delete_parser = switch_subparsers.add_parser('delete',
                                                            parents=[get_name])

        switch_show = switch_subparsers.add_parser('show',
                                                   parents=[get_name])

        switch_list = switch_subparsers.add_parser('list')

        # user parser
        user_register_parser = user_subparsers.add_parser('register',
                                                          parents=[get_name])
        user_register_parser.add_argument('password')
        user_register_parser.add_argument('--admin', action='store_true')

        user_delete_parser = user_subparsers.add_parser('delete',
                                                        parents=[get_name])

        user_connect = user_subparsers.add_parser('connect',
                                                  parents=[get_name])
        user_connect.add_argument('--project', required=True)

        user_disconnect = user_subparsers.add_parser('disconnect',
                                                     parents=[get_name])
        user_disconnect.add_argument('--project', required=True)

        self.parser = parser

    def getCommandFramework(self):
        return self.parser
