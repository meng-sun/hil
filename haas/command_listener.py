import argparse

class confirm(argparse.Action):
    def __init__(self,option_strings,dest,nargs=None,**kwargs):
        super(confirm, self).__init__(option_strings,dest,**kwargs)
    def __call__(self,parser,namespace,values,option_string=None):
        confirm = input("are you sure about this change? [y/n] to continue\n")
        if confirm == "y":
            setattr(namespace,self.dest,values)

class CommandFramework(object):
    # TODO documentation

    def __init__(self):
        parser = argparse.ArgumentParser(usage='haas')
        subcommand_parsers = parser.add_subparsers()

        # startup commands
        serve_parser = subcommand_parsers.add_parser('serve', help="todo")
        serve_parser.add_argument('port', type=int, help="2")
        
        serve_networks_parser = subcommand_parsers.add_parser('serveNetworks', help="1")
        
        # parent parsers
        get_name = argparse.ArgumentParser(add_help=False)
        get_name.add_argument('name', metavar='<object name>')
        get_type = argparse.ArgumentParser(add_help=False)
        get_type.add_argument('type', metavar='<object type>')

        get_subtype_details = argparse.ArgumentParser(add_help=False)
        get_subtype_details.add_argument('host', metavar='<host>')
        get_subtype_details.add_argument('user', metavar= '<username>')
        get_subtype_details.add_argument('password', metavar='<password>')

        get_names = argparse.ArgumentParser(add_help=False)
        get_types = argparse.ArgumentParser(add_help=False)
        get_names.add_argument('name', metavar='<object name>', action='append')
        get_types.add_argument('type', metavar='<object type>', action='append')

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


        
        node_register = node_subparsers.add_parser('register')
        node_register_subtype = node_register.add_subparsers()
        ipmi_node_register = node_register_subtype.add_parser('ipmi', parents = [get_name, get_subtype_details])
        mock_node_register = node_register_subtype.add_parser('mock', parents = [get_name, get_subtype_details])
        
        node_delete = node_subparsers.add_parser('delete')

        node_disconnect = node_subparsers.add_parser('disconnect')
        node_disconnect_partners = node_disconnect.add_subparsers()
        node_disconnect_network = node_disconnect_partners.add_parser('network')
        node_disconnect_project = node_disconnect_partners.add_parser('project')
        node_disconnect_nic = node_disconnect_partners.add_parser('nic')

        # node_reset = node_subparsers.add_parser('reset')
        # reset children falls under reset?

        node_connect = node_subparsers.add_parser('connect')
        node_connect_partners = node_connect.add_subparsers()
        node_connect_network = node_connect_partners.add_parser('network')
        node_connect_project = node_connect_partners.add_parser('project')
        node_connect_nic = node_connect_partners.add_parser('nic')

        node_show = node_subparsers.add_parser('show')


        network_register = network_subparsers.add_parser('register')
        
        network_delete = network_subparsers.add_parser('delete')
        network_delete.add_argument('name', action = confirm)
        # confirm doesn't work properly yet and probably should also get put on reset        
        network_disconnect = network_subparsers.add_parser('disconnect')
        network_disconnect_partners = network_disconnect.add_subparsers()
        network_disconnect_node = network_disconnect_partners.add_parser('node')
        network_disconnect_project = network_disconnect_partners.add_parser('project')
        # access check is still done through api
        
        # network_reset = network_subparsers.add_parser('reset')
        
        network_connect = network_subparsers.add_parser('connect')
        network_connect_partners = network_connect.add_subparsers()
        network_connect_project = network_connect_partners.add_parser('project')
        network_connect_node = network_connect_partners.add_parser('node')

        network_show = network_subparsers.add_parser('show')
 


        nic_register = nic_subparsers.add_parser('register')

        nic_delete = nic_subparsers.add_parser('delete')

        nic_disconnect = nic_subparsers.add_parser('disconnect')
        nic_disconnect_partners = nic_disconnect.add_subparsers()
        nic_disconnect_node = nic_disconnect_partners.add_parser('node')
        nic_disconnect_port = nic_disconnect_partners.add_parser('port')

        nic_connect = nic_subparsers.add_parser('connect')
        nic_connect_partners = nic_connect.add_subparsers()
        nic_connect_port = nic_connect_partners.add_parser('port')
        nic_connect_node = nic_connect_partners.add_parser('node')

        nic_show = nic_subparsers.add_parser('show')



        project_register = project_subparsers.add_parser('register')

        project_delete = project_subparsers.add_parser('delete')

        project_disconnect = project_subparsers.add_parser('disconnect')
        project_disconnect_partners = project_disconnect.add_subparsers()
        project_disconnect_node = project_disconnect_partners.add_parser('node')
        project_disconnect_user = project_disconnect_partners.add_parser('user')
        project_disconnect_network = project_disconnect_partners.add_parser('network')


        project_connect = project_subparsers.add_parser('connect')
        project_connect_partners = project_connect.add_subparsers()
        project_connect_network = project_connect_partners.add_parser('network')
        project_connect_node = project_connect_partners.add_parser('node')
        project_connect_user = project_connect_partners.add_parser('user')


        project_show = project_subparsers.add_parser('show')




        user_register = user_subparsers.add_parser('register')

        user_delete = user_subparsers.add_parser('delete')

        user_disconnect = user_subparsers.add_parser('disconnect')
        user_disconnect_partners = user_disconnect.add_subparsers()
        user_disconnect_project = user_disconnect_partners.add_parser('project')


        user_connect = user_subparsers.add_parser('connect')
        user_connect_partners = user_connect.add_subparsers()
        user_connect_project = user_connect_partners.add_parser('project')


        user_show = user_subparsers.add_parser('show')



        port_register = port_subparsers.add_parser('register')

        port_delete = port_subparsers.add_parser('delete')

        port_disconnect = port_subparsers.add_parser('disconnect')
        port_disconnect_partners = port_disconnect.add_subparsers()
        port_disconnect_nic = port_disconnect_partners.add_parser('nic')
        port_disconnect_switch = port_disconnect_partners.add_parser('switch')


        port_connect = port_subparsers.add_parser('connect')
        port_connect_partners = port_connect.add_subparsers()
        port_connect_nic = port_connect_partners.add_parser('nic')
        port_connect_switch = port_connect_partners.add_parser('switch')


        port_show = port_subparsers.add_parser('show')





        switch_register = switch_subparsers.add_parser('register')
        switch_register_subtype = switch_register.add_subparsers()

        register_nexus_switch = switch_register_subtype.add_parser('nexus',parents=[get_name, get_subtype_details])
        register_nexus_switch.add_argument('dummy vlan')
        register_mock_switch = switch_register_subtype.add_parser('mock',parents=[get_name, get_subtype_details])
        register_powerconnect55xx_switch = switch_register_subtype.add_parser('powerconnect55xx',
                                           parents=[get_name, get_subtype_details])
        register_brocade_switch = switch_register_subtype.add_parser('brocade',parents=[get_name, get_subtype_details])
        register_brocade_switch.add_argument('interface type')



        switch_delete = switch_subparsers.add_parser('delete')
        
        switch_disconnect = switch_subparsers.add_parser('disconnect')
        switch_disconnect_partners = switch_disconnect.add_subparsers()
        switch_disconnect_port = switch_disconnect_partners.add_parser('port')
        
        # switch_reset = switch_subparsers.add_parser('reset')
        
        switch_connect = switch_subparsers.add_parser('connect')
        switch_connect_partners = switch_connect.add_subparsers()
        switch_connect_port = switch_connect_partners.add_parser('port')

        switch_show = switch_subparsers.add_parser('show')


        self.parser = parser



    def getCommandFramework(self):
        return self.parser
