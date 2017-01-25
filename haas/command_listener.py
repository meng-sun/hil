class CommandListener(object):
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
        list_nodes_parser.set_defaults(func=list_nodes)

        list_projnodes_parser = subcommand_parsers.add_parser('list_project_nodes', help="1")
        list_projnodes_parser.add_argument('project', help="3")
        list_projnodes_parser.set_defaults(func=list_project_nodes)

        #these are actual parsers
        #PARENT PARSERS: shared options
        # TODO check if we can reuse arg names
        get_name = argparse.ArgumentParser(add_help=False)
        get_name.add_argument('name', metavar='<object name>')

        get_type = argparse.ArgumentParser(add_help=False)
        get_type.add_argument('type', metavar='<object type>')

        #ACTIONS: register, delete, connect, disconnect, reset, list, (replace)
        register_parser = subcommand_parsers.add_parser('register', add_help=False)
        register_parser_options = register_parser.add_subparsers()

        register_node = register_parser_options.add_parser('node', parents=[get_name])
        register_node.add_argument('name')
        register_node.add_argument('obm_type')
        # Required is set to true since others are unsupported
        register_node.add_argument('--ipmi', nargs=3, metavar=('host','user', 'password'), required=True)
        register_node.set_defaults(func=node_register)

        # TODO register network, user, project, headnode, switch, port
        register_network = register_parser_options.add_parser('network', parents=[get_name])
        register_network.add_argument('--project')
        register_network.add_argument('--owner')
        register_network.add_argument('--access')
        register_network.add_argument('--id')
        register_network.add_argument('--simple', action='store_true')
        if register_network.parse_args().simple:
            register_network.set_defaults(func=network_create_simple)
        else:
            register_network.set_defaults(func=network_create)
        #needs to be one func if just project and a diff if teh other three!!!

        #register set for user
        register_user = register_parser_options.add_parser('user', parents=[get_name])
        register_user.add_argument('username')
        register_user.add_argument('--password', '--pass', required=True)
        register_user.add_argument('--admin', action='store_true')
        register_user.set_defaults(func=user_create)

        #register set for project
        register_project = register_parser_options.add_parser('project', parents=[get_name])
        register_project.add_argument('name')
        register_project.set_defaults(func=project_create)

        #register set for switch
        register_switch = register_parser_options.add_parser('switch', parents=[get_name])
        register_switch.add_argument('name')
        register_switch.add_argument('obm_type')
        register_switch.add_argument('--ipmi', nargs=3, metavar=('host','user', 'password'), required=True)
        register_switch.set_defaults(func=switch_register)

        #register set for nic
        register_nic = register_parser_options.add_parser('nic', parents=[get_name])
        register_nic.add_argument('name')
        register_nic.add_argument('--node', required=True)
        register_nic.add_argument('--macaddr', required=True)
        register_nic.set_defaults(func=node_register_nic)

        #register set for headnode
        register_hnode = register_parser_options.add_parser('headnode', parents=[get_name])
        register_hnode.add_argument('name')
        register_hnode.add_argument('--project', required=True)
        register_hnode.add_argument('--image', '--img', required=True)
        register_hnode.set_defaults(func=headnode_create)

        #register set for hnic
        register_hnic = register_parser_options.add_parser('hnic', parents=[get_name])
        register_hnic.add_argument('name')
        register_hnic.add_argument('--headnode', '--hnode', '--hn', required=True)
        register_hnic.set_defaults(func=headnode_create_hnic)

        #register set for port
        register_port = register_parser_options.add_parser('port', parents=[get_name])
        register_port.add_argument('name')
        register_port.add_argument('--switch', required=True)
        register_port.set_defaults(func=port_register)

        # TODO all of delete

        #show set
        show_parser = subcommand_parsers.add_parser('show')
        show_parser.add_argument('name')
        name = 'show_' + show_parser.parse_args().name
        '''not sure this will work'''
        show_parser.set_defaults(func=name)

        #list stuff
        list_parser = subcommand_parsers.add_parser('list', parents=[get_name])
        list_projects = list_parser_options.add_parser('project')
        list_projects.set_defaults(func=list_projects)        
        list_switches = list_parser_options.add_parser('switch')
        list_switches.set_defaults(func=list_switches)
        
        list_networks = list_parser_options.add_parser('network')
        list_networks.set_defaults(func=list_networks)
        one_or = list_networks.add_mutually_exclusive_group()
        one_or.add_argument('--project', '--proj')
        one_or.add_arguments('--all', action="store_true")
        list_networks.add_argument()
        if not list_networks.parse_args().project is None:        
            list_networks.set_defaults(func=list_project_networks)
        
        list_nodes = list_parser_options.add_parser('node')
        list_nodes.add_argument('--project', '--proj')
        list_nodes.add_argument('--network', '--net')
        list_nodes.set_defaults(func=list_nodes)
        if not list_nodes.parse_args().project is None:
            list_nodes.set_defaults(func=list_project_nodes)
        if not list_nodes.parse_args().network is None:
            list.nodes.set_defaults(func=list_network_attachments)
        list_nodes.add_argument('--free', action="store_true")
        list_nodes.add_argument('--all', action="store_true")
        
        
        
        

        #All of disconnect and connect
        remove_parser = subcommand_parsers.add_parser('disconnect', 'remove', 'detach')
        connect_parser = subcommand_parsers.add_parser('connect', 'add', 'attach')
        args = parser.parse_args()
        obj_list = ['project', 'node', 'network', 'nic', 'headnode',
                    'user', 'hnic', 'switch', 'port']
        true = []
        for list_item in obj_list:
            if not args.list_item is None:
                true.append(list_item)
        '''project = not args.project is None
        node =  not args.node is None
        network = not args.network is None
        nic = not  args.nic is None
        headnode = not args.headnode is None
        user = not args.user is None
        hnic = not args.hnic is None
        switch = not args.switch is None
        port = not args.port is None'''

        #assign functions for connect and disconnect
        if 'user' in true and 'project' in true and len(true) == 2:
            remove_parser.set_defaults(func=user_remove_project)
            connect_parser.set_defaults(func=user_add_project)
        elif 'project' in true and 'network' in true and len(true) == 2:
            remove_parser.set_defaults(func=network_revoke_project_access)
            connect_parser.set_defaults(func=network_grant_project_access)
        elif 'project' in true and 'node' in true and len(true) == 2:
            remove_parser.set_defaults(func=project_detach_node)
            connect_parser.set_defaults(func=project_connect_node)
        elif 'node' in true and 'nic' in true and 'network' in true and len(true) == 3:
            remove_parser.set_defaults(func=node_detach_network)
            connect_parser.set_defaults(func=node_connect_network)
        elif 'headnode' in true and 'hnic' in true:
            if len(true) == 2:
                remove_parser.set_defaults(func=headnode_detach_network)
            if 'network' in true and len(true) == 3:
                connect_parser.set_defaults(func=headnode_connect_network)
        elif 'port' in true and 'switch' in true:
            if len(true) == 2:
                remove_parser.set_defaults(func=port_detach_nic)
            if 'node' in true and 'nic' in true and len(true) == 4:
                connect_parser.set_defaults(func=port_connect_nic)
        else:
            '''error'''

        # TODO connect
        connect_parser = subcommand_parsers.add_parser('connect')
        connect_parser_options = connect_parser.add_subparsers()
        node_connect_network = connect_parser_options.add_parser('idk')

        print "tab completed"
        argcomplete.autocomplete(parser)
        print sys.argv
        args = parser.parse_args(sys.argv[1:])
        try:
            args.func(args)
        except TypeError:
            print "missing a required flag option"
            raise InvalidAPIArgumentsException()
        print args
        print "EOF"