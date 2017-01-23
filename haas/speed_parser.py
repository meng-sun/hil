import argparse
import argcomplete

def getCommandListener():
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
    register_node.add_argument('obm_type')
    # Required is set to true since others are unsupported
    register_node.add_argument('--ipmi', nargs=3, metavar=('host','user', 'password'), required=True)
    #register_node.set_defaults(func=node_register)
    register_network = register_parser_options.add_parser('network', parents=[get_name])
    connect_parser = subcommand_parsers.add_parser('connect')
    connect_parser_options = connect_parser.add_subparsers()
    node_connect_network = connect_parser_options.add_parser('idk')
    #argcomplete.autocomplete(parser)
    print "EOF"
    return parser
