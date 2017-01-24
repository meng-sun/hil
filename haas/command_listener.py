import argparse

class CommandFramework(object):
    """A decorator for CLI commands.

    This decorator firstly adds the function to a dictionary of valid CLI
    commands, secondly adds exception handling for when the user passes the
    wrong number of arguments, and thirdly generates a 'usage' description and
    """
    # TODO documentation

    def __init__(self):
        parser = argparse.ArgumentParser(usage='haas')
        subcommand_parsers = parser.add_subparsers()

        #these are examples: 
        list_nodes_parser = subcommand_parsers.add_parser('list_nodes', help="1")
        list_nodes_parser.add_argument('is_free', default='all', help="2")
        #list_nodes_parser.set_defaults(func=list_nodes)

        list_projnodes_parser = subcommand_parsers.add_parser('list_project_nodes', help="1")
        list_projnodes_parser.add_argument('project', help="3")
        #list_projnodes_parser.set_defaults(func=list_project_nodes)

        #these are actual parsers
        #PARENT PARSERS: shared options
        # TODO check if we can reuse arg names
        get_name = argparse.ArgumentParser(add_help=False)
        get_name.add_argument('name', metavar='<object name>')

        get_type = argparse.ArgumentParser(add_help=False)
        get_type.add_argument('type', metavar='<object type>')

        #ACTIONS: register, delete, connect, disconnect, reset, list, (replace)
        register_parser = subcommand_parsers.add_parser('register')
        register_parser_options = register_parser.add_subparsers()

        register_node = register_parser_options.add_parser('node', parents=[get_name])
        register_node.add_argument('name')
        register_node.add_argument('obm_type')
        # Required is set to true since others are unsupported
        register_node.add_argument('--ipmi', nargs=3, metavar=('host','user', 'password'), required=True)        
        #register_node.set_defaults(func=node_register)

        # TODO register network, user, project, headnode, switch, port
        register_network = register_parser_options.add_parser('network', parents=[get_name])
        register_network.add_argument('--project')
        register_network.add_argument('--owner')
        register_network.add_argument('--access')
        register_network.add_argument('--id')
        register_network.add_argument('--simple', action='store_true')
        #if register_network.parse_args().simple:
            #register_network.set_defaults(func=network_create_simple)
        #else:
         #   register_network.set_defaults(func=network_create)
        #needs to be one func if just project and a diff if teh other three!!!

        #register set for user
        register_user = register_parser_options.add_parser('user', parents=[get_name])
        register_user.add_argument('username')
        register_user.add_argument('--password', '--pass', required=True)
        register_user.add_argument('--admin', action='store_true')
        #register_user.set_defaults(func=user_create)

        #register set for project
        register_project = register_parser_options.add_parser('project', parents=[get_name])
        register_project.add_argument('name')
        #register_project.set_defaults(func=project_create)

        #register set for switch
        register_switch = register_parser_options.add_parser('switch', parents=[get_name])
        register_switch.add_argument('name')
        register_switch.add_argument('obm_type')
        register_switch.add_argument('--ipmi', nargs=3, metavar=('host','user', 'password'), required=True)
        #register_switch.set_defaults(func=switch_register)

        #register set for nic
        register_nic = register_parser_options.add_parser('nic', parents=[get_name])
        register_nic.add_argument('name')
        register_nic.add_argument('--node', required=True)
        register_nic.add_argument('--macaddr', required=True)
        #register_nic.set_defaults(func=node_register_nic)

        #register set for headnode
        register_hnode = register_parser_options.add_parser('headnode', parents=[get_name])
        register_hnode.add_argument('name')
        register_hnode.add_argument('--project', required=True)
        register_hnode.add_argument('--image', '--img', required=True)
        #register_hnode.set_defaults(func=headnode_create)

        #register set for hnic
        register_hnic = register_parser_options.add_parser('hnic', parents=[get_name])
        register_hnic.add_argument('name')
        register_hnic.add_argument('--headnode', '--hnode', '--hn', required=True)
        #register_hnic.set_defaults(func=headnode_create_hnic)

        #register set for port
        register_port = register_parser_options.add_parser('port', parents=[get_name])
        register_port.add_argument('name')
        register_port.add_argument('--switch', required=True)
        #register_port.set_defaults(func=port_register)

        # TODO all of delete

        #All of disconnect
        remove_parser = subcommand_parsers.add_parser('disconnect')


        # TODO connect
        connect_parser = subcommand_parsers.add_parser('connect')
        connect_parser_options = connect_parser.add_subparsers()
        node_connect_network = connect_parser_options.add_parser('idk')

        self.parser = parser

def getCommandFramework():
    cF = CommandFramework()
    return cF.parser
