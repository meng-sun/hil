# Copyright 2013-2014 Massachusetts Open Cloud Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.  See the License for the specific language
# governing permissions and limitations under the License.

"""This module implements the HaaS command line tool."""
from haas import config, server
from haas.config import cfg

import inspect
import json
import os
import requests
import sys
import urllib
import schema
import abc
import argparse
import subprocess

from functools import wraps

command_dict = {}
usage_dict = {}
MIN_PORT_NUMBER = 1
MAX_PORT_NUMBER = 2**16 - 1

class confirm(argparse.Action):
    def __init__(self,option_strings,dest,nargs=None,**kwargs):
        super(confirm, self).__init__(option_strings,dest,nargs,**kwargs)
    def __call__(self,parser,namespace,values,option_string=None):
        print "are you sure about this change? [y/n] to continue\n"
        #confirm = subprocess.Popen(['read','-n','1','confirm','\n','echo','$confirm'], shell=True, stdout=subprocess.PIPE)
        #if confirm == "y":
        setattr(namespace,self.dest,values)
        print "est"

def set_func(function):
    class func_caller(argparse.Action):
        def __init__(self,option_strings,dest,nargs=None,**kwargs):
            super(func_caller, self).__init__(option_strings,dest,nargs,**kwargs)
        def __call__(self,parser,namespace,values,option_string=None):
            setattr(namespace, 'func', function)
            setattr(namespace,self.dest,values)
    return func_caller


class HTTPClient(object):
    """An HTTP client.

    Makes HTTP requests on behalf of the HaaS CLI. Responsible for adding
    authentication information to the request.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def request(method, url, data=None, params=None):
        """Make an HTTP request

        Makes an HTTP request on URL `url` with method `method`, request body
        `data`(if supplied) and query parameter `params`(if supplied). May add
        authentication or other backend-specific information to the request.

        Parameters
        ----------

        method : str
            The HTTP method to use, e.g. 'GET', 'PUT', 'POST'...
        url : str
            The URL to act on
        data : str, optional
            The body of the request
        params : dictionary, optional
            The query parameter, e.g. {'key1': 'val1', 'key2': 'val2'},
            dictionary key can't be `None`

        Returns
        -------

        requests.Response
            The HTTP response
        """


class RequestsHTTPClient(requests.Session, HTTPClient):
    """An HTTPClient which uses the requests library.

    Note that this doesn't do anything over `requests.Session`; that
    class already implements the required interface. We declare it only
    for clarity.
    """


class KeystoneHTTPClient(HTTPClient):
    """An HTTPClient which authenticates with Keystone.

    This uses an instance of python-keystoneclient's Session class
    to do its work.
    """

    def __init__(self, session):
        """Create a KeystoneHTTPClient

        Parameters
        ----------

        session : keystoneauth1.Session
            A keystone session to make the requests with
        """
        self.session = session

    def request(self, method, url, data=None, params=None):
        """Make an HTTP request using keystone for authentication.

        Smooths over the differences between python-keystoneclient's
        request method that specified by HTTPClient
        """
        # We have to import this here, since we can't assume the library
        # is available from global scope.
        from keystoneauth1.exceptions.http import HttpError

        try:
            # The order of these parameters is different that what
            # we expect, but the names are the same:
            return self.session.request(method=method,
                                        url=url,
                                        data=data,
                                        params=params)
        except HttpError as e:
            return e.response


# An instance of HTTPClient, which will be used to make the request.
http_client = None


class InvalidAPIArgumentsException(Exception):
    pass


def setup_http_client():
    """Set `http_client` to a valid instance of `HTTPClient`

    Sets http_client to an object which makes HTTP requests with
    authentication. It chooses an authentication backend as follows:

    1. If the environment variables HAAS_USERNAME and HAAS_PASSWORD
       are defined, it will use HTTP basic auth, with the corresponding
       user name and password.
    2. If the `python-keystoneclient` library is installed, and the
       environment variables:

           * OS_AUTH_URL
           * OS_USERNAME
           * OS_PASSWORD
           * OS_PROJECT_NAME

       are defined, Keystone is used.
    3. Oterwise, do not supply authentication information.

    This may be extended with other backends in the future.
    """
    global http_client
    # First try basic auth:
    basic_username = os.getenv('HAAS_USERNAME')
    basic_password = os.getenv('HAAS_PASSWORD')
    if basic_username is not None and basic_password is not None:
        http_client = RequestsHTTPClient()
        http_client.auth = (basic_username, basic_password)
        return
    # Next try keystone:
    try:
        from keystoneauth1.identity import v3
        from keystoneauth1 import session
        os_auth_url = os.getenv('OS_AUTH_URL')
        os_password = os.getenv('OS_PASSWORD')
        os_username = os.getenv('OS_USERNAME')
        os_user_domain_id = os.getenv('OS_USER_DOMAIN_ID') or 'default'
        os_project_name = os.getenv('OS_PROJECT_NAME')
        os_project_domain_id = os.getenv('OS_PROJECT_DOMAIN_ID') or 'default'
        if None in (os_auth_url, os_username, os_password, os_project_name):
            raise KeyError("Required openstack environment variable not set.")
        auth = v3.Password(auth_url=os_auth_url,
                           username=os_username,
                           password=os_password,
                           project_name=os_project_name,
                           user_domain_id=os_user_domain_id,
                           project_domain_id=os_project_domain_id)
        sess = session.Session(auth=auth)
        http_client = KeystoneHTTPClient(sess)
        return
    except (ImportError, KeyError):
        pass
    # Finally, fall back to no authentication:
    http_client = requests.Session()


class FailedAPICallException(Exception):
    pass


def check_status_code(response):
    if response.status_code < 200 or response.status_code >= 300:
        sys.stderr.write('Unexpected status code: %d\n' % response.status_code)
        sys.stderr.write('Response text:\n')
        sys.stderr.write(response.text + "\n")
        raise FailedAPICallException()
    else:
        sys.stdout.write(response.text + "\n")


# TODO: This function's name is no longer very accurate.  As soon as it is
# safe, we should change it to something more generic.
def object_url(*args):
    # Prefer an environmental variable for getting the endpoint if available.
    url = os.environ.get('HAAS_ENDPOINT')
    if url is None:
        url = cfg.get('client', 'endpoint')

    for arg in args:
        url += '/' + urllib.quote(arg, '')
    return url


# Helper functions for making HTTP requests against the API.
#    Uses the global variable `http_client` to make the request.
#
#    Arguments:
#
#        `url` - The url to make the request to
#        `data` - the body of the request (for PUT, POST and DELETE)
#        `params` - query parameters (for GET)

def do_put(url, data={}):
    check_status_code(http_client.request('PUT', url, data=json.dumps(data)))


def do_post(url, data={}):
    check_status_code(http_client.request('POST', url, data=json.dumps(data)))


def do_get(url, params=None):
    check_status_code(http_client.request('GET', url, params=params))


def do_delete(url):
    check_status_code(http_client.request('DELETE', url))

# outdated
def cmd(f):
    """A decorator for CLI commands.

    This decorator firstly adds the function to a dictionary of valid CLI
    commands, secondly adds exception handling for when the user passes the
    wrong number of arguments, and thirdly generates a 'usage' description and
    puts it in the usage dictionary.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            f(*args, **kwargs)
        except TypeError:
            # TODO TypeError is probably too broad here.
            sys.stderr.write('Invalid arguements.  Usage:\n')
            help(f.__name__)
            raise InvalidAPIArgumentsException()
    command_dict[f.__name__] = wrapped

    def get_usage(f):
        args, varargs, _, _ = inspect.getargspec(f)
        showee = [f.__name__] + ['<%s>' % name for name in args]
        args = ' '.join(['<%s>' % name for name in args])
        if varargs:
            showee += ['<%s...>' % varargs]
        return ' '.join(showee)
    usage_dict[f.__name__] = get_usage(f)
    return wrapped


class CommandListener(object):
    """Creates argparse command line interface for calling API functions.
    """
    # TODO redo documentation and help statements

    def __init__(self):
        parser = argparse.ArgumentParser(usage='haas')
        subcommand_parsers = parser.add_subparsers()

        # Startup Commands
        serve_parser = subcommand_parsers.add_parser('serve', help="todo")
        serve_parser.add_argument('port', type=int, help="2")
        serve_parser.set_defaults(func=serve)

        serve_networks_parser = subcommand_parsers.add_parser('serveNetworks', help="1")
        serve_networks_parser.set_defaults(func=serve_networks)

        #PARENT PARSERS: shared options
        get_name = argparse.ArgumentParser(add_help=False)
        get_name.add_argument('name', metavar='<object name>')

        get_type = argparse.ArgumentParser(add_help=False)
        get_type.add_argument('type', metavar='<object type>')

        get_subtype_details = argparse.ArgumentParser(add_help=False)
        #get_subtype_details.add_argument('--host', metavar='<host>')
        #get_subtype_details.add_argument('--user', metavar= '<username>')
        #get_subtype_details.add_argument('--password',metavar='<password>')
        
        # get_names = argparse.ArgumentParser(add_help=False)
        # get_types = argparse.ArgumentParser(add_help=False)
        # get_names.add_argument('name', metavar='<object name>', action='append')
        # get_types.add_argument('type', metavar='<object type>', action='append')

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



        
        node_register_parser = node_subparsers.add_parser('register', parents = [get_name])
        #node_register_subtype = node_register_parser.add_subparsers()
        #ipmi_node = node_register_subtype.add_parser('ipmi', parents = [get_name, get_subtype_details])
        #mock_node = node_register_subtype.add_parser('mock', parents = [get_name, get_subtype_details])
        #ipmi_node.set_defaults(func=ipmi_node_register)
        #mock_node.set_defaults(func=mock_node_register)
        node_register_subtype = node_register_parser.add_mutually_exclusive_group(required=True)
        node_register_subtype.add_argument('--mock', nargs=3, metavar=('host','user','password') )
        node_register_subtype.add_argument('--impi', nargs=3, metavar=('host','user','password') )
        node_register_parser.set_defaults(func=node_register)
        
        node_delete_parser = node_subparsers.add_parser('delete', parents = [get_name])
        #node_delete_parser.add_argument('--name', action=confirm)
        # fix confirm action, also add in recursive function
        node_delete_parser.set_defaults(func=node_delete)

        # shortened
        node = argparse.ArgumentParser(add_help=False)
        node.add_argument('node_name')
        nic = argparse.ArgumentParser(add_help=False)
        nic.add_argument('nic_name')
        node_network_relationship = argparse.ArgumentParser(add_help=False)
        node_network_relationship.add_argument('node_name')
        node_network_relationship.add_argument('nic_name')
        node_network_relationship.add_argument('network_name')
        node_project_relationship = argparse.ArgumentParser(add_help=False)
        node_project_relationship.add_argument('node_name')
        node_project_relationship.add_argument('project_name')


        node_disconnect = node_subparsers.add_parser('disconnect',parents=[get_name])
        node_disconnects = node_disconnect.add_mutually_exclusive_group()
        node_disconnects.add_argument('--network',action=set_func(empty),nargs=2, 
                                      metavar=('<network name>','<nic name>')
                                      )
        node_disconnects.add_argument('--project',metavar='<project name>',
                                      action=set_func(project_remove_node))
        node_disconnects.add_argument('--nic', metavar='<nic name>')
        node_disconnect.set_defaults(func=empty)
        #node_disconnect_partners = node_disconnect.add_subparsers()
        #node_disconnect_network = node_disconnect_partners.add_parser('network', parents=[get_name])
        #node_disconnect_network.set_defaults(func=node_remove_network)
        #node_disconnect_project = node_disconnect_partners.add_parser('project', parents =[node_project_relationship])
        #node_disconnect_project.set_defaults(func=project_remove_node)
        #node_disconnect_nic = node_disconnect_partners.add_parser('nic',parents=[nic,node])
        #node_disconnect_nic.set_defaults(func=node_delete_nic)
        # node_reset = node_subparsers.add_parser('reset')
        # reset children falls under reset?

        node_connect = node_subparsers.add_parser('connect')
        node_connect_partners = node_connect.add_subparsers()
        node_connect_net = node_connect_partners.add_parser('network')
        node_connect_net.add_argument('channel')
        node_connect_net.set_defaults(func=node_connect_network)
        node_connect_project = node_connect_partners.add_parser('project')
        node_connect_nic = node_connect_partners.add_parser('nic')

        node_show = node_subparsers.add_parser('show')
        # add list
        #switch parsers
         
        #headnode statements
        hn_reg = headnode_subparsers.add_parser('register', parents = [get_name])
        hn_reg.add_argument('--project', '--proj')
        hn_reg.add_argument('--image', '--img')
        hn_delete = headnode_subparsers.add_parser('delete', parents = [get_name])
        hn_connect = headnode_subparsers.add_parser('connect', parents = [get_name])
        hn_connect.add_argument('--network')
        hn_connect.add_argument('--hnic')
        hn_detach = headnode_subparsers.add_parser('disconnect', parents = [get_name])
        hn_detach.add_argument('---hnic')
        hn_start = headnode_subparsers.add_parser('start', parents = [get_name])
        hn_stop = headnode_subparsers.add_parser('stop', parents = [get_name])
        show_hn = headnode_subparsers.add_parser('show', parents = [get_name])
        list_hn =  headnode_subparsers.add_parser('list')
        list_hn.add_argument('--project', '-proj')
        list_hn.add_argument('-i', '--images')
        
        #nic statements
        #nic_parser.add_argument('--node')
        #nic_parser.add_argument('--switch')
        #nic_parser.add_argument('--port')
        nic_register = nic_subparsers.add_parser('register', parents = [get_name])
        nic_register.add_argument('--macaddr')
        nic_delete = nic_subparsers.add_parser('delete', parents = [get_name])
        nic_connect = nic_subparsers.add_parser('connect', parents = [get_name])
        nic_disconnect = nic_subparsers.add_parser('disconnect')
        
        #hnic statements
        hnic_parser.add_argument('--hnode', '--headnode')
        hnic_register = hnic_subparsers.add_parser('register', parents = [get_name])
        hnic_delete = hnic_subparsers.add_parser('delete')
        #hnic_detach = hnic_subparsers.add_parser('detach')
        #hnic_connect = hnic_subparsers.add_parser('connect')
        #hnic_connect.add_argument('--network', '--net')
        
        #port statements 
        port_parser.add_argument('--switch')
        port_register_parser = port_subparsers.add_parser('register', parents = [get_name])        
        port_delete_parser = port_subparsers.add_parser('delete', parents = [get_name])
        port_detach_nic_parser = port_subparsers.add_parser('disconnect', parents = [get_name])
        port_connect = port_subparsers.add_parser('connect', parents = [get_name])
        port_connect.add_argument('--node')
        port_connect.add_argument('--nic')
        # current both types are supported
        

        """
        node_parser = subcommand_parsers.add_parser('node')

        register_parser = subcommand_parsers.add_parser('register',help='todo makes the thing')
        register_parser_options = register_parser.add_subparsers()

        register_node = register_parser_options.add_parser('node', parents=[get_name])
        register_node.add_argument('name')
        register_node.add_argument('subtype')
        # Required is set to true since other obm_types are currently unsupported
        register_node.add_argument('--ipmi', nargs=3, metavar=('host','user', 'password'), required=True)
        register_node.set_defaults(func=node_register)
        
        # register set for network
        register_network = register_parser_options.add_parser('network', parents=[get_name])
        # TODO decide whether to use two different commands for simple v reg network
        # or to create positional arguments for owner/access/id and proj and mutually
        # exclude those
        register_simple_network = register_parser_options.add_parser('simpleNet',parents=[get_name])
        register_network.add_argument('--owner',required=True)
        register_network.add_argument('--access',required=True)
        register_network.add_argument('--id',dest='net_id',required=True)
        register_network.set_defaults(func=network_create)

        register_simple_network.add_argument('--project',required=True)
        register_simple_network.set_defaults(func=network_create_simple)

        #register set for user
        register_user = register_parser_options.add_parser('user', parents=[get_name])
        register_user.add_argument('--password', '--pass', required=True)
        register_user.add_argument('--admin', action='store_true', dest='is_admin')
        register_user.set_defaults(func=user_create)

        #register set for project
        register_project = register_parser_options.add_parser('project', parents=[get_name])
        register_project.set_defaults(func=project_create)

        #register set for switch
        register_switch = register_parser_options.add_parser('switch',add_help=False)
        register_switch.set_defaults(switch_register)
        switch_type = register_switch.add_subparsers()
        register_nexus_switch = switch_type.add_parser('nexus',parents=[get_name, get_subtype_details])
        register_nexus_switch.add_argument('<dummy vlan>', dest = 'dummy_vlan')
        register_nexus_switch.add_argument('subtype', default='nexus')
        register_mock_switch = switch_type.add_parser('mock',parents=[get_name, get_subtype_details])
        register_powerconnect55xx_switch = switch_type.add_parser('powerconnect55xx',
                                           parents=[get_name, get_subtype_details])
        register_brocade_switch = switch_type.add_parser('brocade',parents=[get_name, get_subtype_details])
        register_brocade_switch.add_argument('<interface type>', dest = 'interface_type')

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
        """
        args = parser.parse_args(sys.argv[1:])
        try:
            print args
            args.func(args)
        except TypeError:
            print "missing a required flag option"
            raise InvalidAPIArgumentsException()

def serve(args):
    try:
        args.port = schema.And(
        schema.Use(int),
        lambda n: MIN_PORT_NUMBER <= n <= MAX_PORT_NUMBER).validate(args.port)
    except schema.SchemaError:
        sys.exit('Error: Invalid port. Must be in the range 1-65535.')
    except Exception as e:
        sys.exit('Unexpected Error!!! \n %s' % e)

    """Start the HaaS API server"""
    if cfg.has_option('devel', 'debug'):
        debug = cfg.getboolean('devel', 'debug')
    else:
        debug = False
    # We need to import api here so that the functions within it get registered
    # (via `rest_call`), though we don't use it directly:
    from haas import model, api, rest
    server.init(stop_consoles=True)
    rest.serve(args.port, debug=debug)


def serve_networks():
    """Start the HaaS networking server"""
    from haas import model, deferred
    from time import sleep
    server.init()
    server.register_drivers()
    server.validate_state()
    model.init_db()
    while True:
        # Empty the journal until it's empty; then delay so we don't tight
        # loop.
        while deferred.apply_networking():
            pass
        sleep(2)


def user_create(args):
    """Create a user <username> with password <password>.

    <is_admin> may be either "admin" or "regular", and determines whether
    the user has administrative priveledges.
    """
    url = object_url('/auth/basic/user', args.name)
    do_put(url, data={
        'password': args.password,
        'is_admin': args.is_admin,
    })


def network_create(args):
    """Create a link-layer <network>. See docs/networks.md for details."""
    url = object_url('network', args.name)
    do_put(url, data={'owner': args.owner,
                      'access': args.access,
                      'net_id': args.net_id})

def network_create_simple(args):
    """Creates a simple <network> owned by project."""
    url = object_url('network', args.name)
    do_put(url, data={'owner': args.project,
                      'access': args.project,
                      'net_id': ""})


def network_delete(network):
    """Delete a <network>"""
    url = object_url('network', network)
    do_delete(url)


def user_delete(username):
    """Delete the user <username>"""
    url = object_url('/auth/basic/user', username)
    do_delete(url)


def list_projects():
    """List all projects"""
    url = object_url('projects')
    do_get(url)


def user_add_project(user, project):
    """Add <user> to <project>"""
    url = object_url('/auth/basic/user', user, 'add_project')
    do_post(url, data={'project': project})


def user_remove_project(user, project):
    """Remove <user> from <project>"""
    url = object_url('/auth/basic/user', user, 'remove_project')
    do_post(url, data={'project': project})


def network_grant_project_access(project, network):
    """Add <project> to <network> access"""
    url = object_url('network', network, 'access', project)
    do_put(url)


def network_remove_project(project, network):
    """Remove <project> from <network> access"""
    url = object_url('network', network, 'access', project)
    do_delete(url)


def project_create(args):
    """Create a <project>"""
    url = object_url('project', args.name)
    do_put(url)


def project_delete(project):
    """Delete <project>"""
    url = object_url('project', project)
    do_delete(url)


def headnode_create(headnode, project, base_img):
    """Create a <headnode> in a <project> with <base_img>"""
    url = object_url('headnode', headnode)
    do_put(url, data={'project': project,
                      'base_img': base_img})


def headnode_delete(headnode):
    """Delete <headnode>"""
    url = object_url('headnode', headnode)
    do_delete(url)


def project_connect_node(project, node):
    """Connect <node> to <project>"""
    url = object_url('project', project, 'connect_node')
    do_post(url, data={'node': node})


def project_remove_node(args):
    """Detach <node> from <project>"""
    url = object_url('project', args.project_name, 'detach_node')
    do_post(url, data={'node': args.node_name})


def headnode_start(headnode):
    """Start <headnode>"""
    url = object_url('headnode', headnode, 'start')
    do_post(url)


def headnode_stop(headnode):
    """Stop <headnode>"""
    url = object_url('headnode', headnode, 'stop')
    do_post(url)


def node_disconnect_redirect(args):
    possibilities = ['network','project','nic']
    poss_func = [node_remove_network, project_remove_node, node_delete_nic]
    for obj in range(len(possibilities)):
        if hasattr(args,possibilities[obj]):
            poss_func[obj](args)

def empty(args):
    print "is empty"


# decide which version of node register to use
def node_register(args):
    """Register a node named <node>, with the given type
        if obm is of type: ipmi then provide arguments
        "ipmi", <hostname>, <ipmi-username>, <ipmi-password>
    """
    obm_api = "http://schema.massopencloud.org/haas/v0/obm/"
    obm_types = ["ipmi", "mock"]
    for obm in obm_types:
        if hasattr(args,obm):
            subtype = obm
 
    details = getattr(args,subtype)
    # Currently the classes are hardcoded
    # In principle this should come from api.py
    # In future an api call to list which plugins are active will be added.

    if subtype in obm_types:
        if len(details) == 3:
            obminfo = {"type": obm_api + subtype, "host": details[0],
                       "user": details[1], "password": details[2]
                       }
        else:
            sys.stderr.write('ERROR: subtype ' + subtype +
                             ' requires exactly 3 arguments\n')
            sys.stderr.write('<hostname> <ipmi-username> <ipmi-password>\n')
            return
    else:
        sys.stderr.write('ERROR: Wrong OBM subtype supplied\n')
        sys.stderr.write('Supported OBM sub-types: ipmi, mock\n')
        return

    url = object_url('node', args.name)
    do_put(url, data={"obm": obminfo})


# problem with this method is that you can't load 
# active subtypes into tab completition
# it will always load all of them 
def mock_node_register(args):
    obm_api = "http://schema.massopencloud.org/haas/v0/obm/"
    obminfo = {"type": obm_api + 'mock', "host": args.host,
                       "user": args.user, "password": args.password
                       }


def ipmi_node_register(args):
    obm_api = "http://schema.massopencloud.org/haas/v0/obm/"
    obminfo = {"type": obm_api + 'ipmi', "host": args.host,
                       "user": args.user, "password": args.password
                       }


def node_delete(args):
    """Delete <node>"""
    url = object_url('node', args.name)
    do_delete(url)



def node_power_cycle(node):
    """Power cycle <node>"""
    url = object_url('node', node, 'power_cycle')
    do_post(url)



def node_power_off(node):
    """Power off <node>"""
    url = object_url('node', node, 'power_off')
    do_post(url)



def node_register_nic(args):
    """
    Register existence of a <nic> with the given <macaddr> on the given <node>
    """
    url = object_url('node', args.node_name, 'nic', args.nic_name)
    do_put(url, data={'macaddr': args.macaddr})



def node_delete_nic(args):
    """Delete a <nic> on a <node>"""
    url = object_url('node', args.node_name, 'nic', args.nic_name)
    do_delete(url)



def headnode_create_hnic(headnode, nic):
    """Create a <nic> on the given <headnode>"""
    url = object_url('headnode', headnode, 'hnic', nic)
    do_put(url)



def headnode_delete_hnic(headnode, nic):
    """Delete a <nic> on a <headnode>"""
    url = object_url('headnode', headnode, 'hnic', nic)
    do_delete(url)



def node_connect_network(args):
    """Connect <node> to <network> on given <nic> and <channel>"""
    url = object_url('node', args.node_name, 'nic', args.nic_name, 'connect_network')
    do_post(url, data={'network': args.network_name,
                       'channel': channel})



def node_remove_network(args):
    """Detach <node> from the given <network> on the given <nic>"""
    if hasattr(args,'network'):
        node = args.name
        nic = args.network[1]
        network = args.network[0]
    else:
        node = args.node[0]
        nic = args.node[1]
        network = args.name
    url = object_url('node', node, 'nic', nic, 'detach_network')
    do_post(url, data={'network': network})



def headnode_connect_network(headnode, nic, network):
    """Connect <headnode> to <network> on given <nic>"""
    url = object_url('headnode', headnode, 'hnic', nic, 'connect_network')
    do_post(url, data={'network': network})



def headnode_remove_network(headnode, hnic):
    """Detach <headnode> from the network on given <nic>"""
    url = object_url('headnode', headnode, 'hnic', hnic, 'detach_network')
    do_post(url)



def switch_register(org_args):
    """Register a switch with name <switch> and
    <subtype>, <hostname>, <username>,  <password>
    eg. haas switch_register mock03 mock mockhost01 mockuser01 mockpass01

    FIXME: current design needs to change. CLI should not know about every
    backend. Ideally, this should be taken care of in the driver itself or
    client library (work-in-progress) should manage it.
    """
    subtype = args.subtype
    args = [org_args.host, org_args.user, org_args.password]
    switch_api = "http://schema.massopencloud.org/haas/v0/switches/"
    if subtype == "nexus":
        args = args.append(org_args.dummy_vlan)
        if len(args) == 4:
            switchinfo = {
                "type": switch_api + subtype,
                "hostname": args[0],
                "username": args[1],
                "password": args[2],
                "dummy_vlan": args[3]}
        else:
            sys.stderr.write(_('ERROR: subtype ' + subtype +
                               ' requires exactly 4 arguments\n'
                               '<hostname> <username> <password>'
                               '<dummy_vlan_no>\n'))
            return
    elif subtype == "mock":
        args = args.mock
        if len(args) == 3:
            switchinfo = {"type": switch_api + subtype, "hostname": args[0],
                          "username": args[1], "password": args[2]}
        else:
            sys.stderr.write('ERROR: subtype ' + subtype +
                             ' requires exactly 3 arguments\n')
            sys.stderr.write('<hostname> <username> <password>\n')
            return
    elif subtype == "powerconnect55xx":
        args = args.powerconnect55xx
        if len(args) == 3:
            switchinfo = {"type": switch_api + subtype, "hostname": args[0],
                          "username": args[1], "password": args[2]}
        else:
            sys.stderr.write(_('ERROR: subtype ' + subtype +
                               ' requires exactly 3 arguments\n'
                               '<hostname> <username> <password>\n'))
            return
    elif subtype == "brocade":
        args = args.brocade
        if len(args) == 4:
            switchinfo = {"type": switch_api + subtype, "hostname": args[0],
                          "username": args[1], "password": args[2],
                          "interface_type": args[3]}
        else:
            sys.stderr.write(_('ERROR: subtype ' + subtype +
                               ' requires exactly 4 arguments\n'
                               '<hostname> <username> <password> '
                               '<interface_type>\n'
                               'NOTE: interface_type refers '
                               'to the speed of the switchports\n '
                               'ex. TenGigabitEthernet, FortyGigabitEthernet, '
                               'etc.\n'))
            return
    else:
        sys.stderr.write('ERROR: Invalid subtype supplied\n')
        return
    url = object_url('switch', switch)
    do_put(url, data=switchinfo)



def switch_delete(switch):
    """Delete a <switch> """
    url = object_url('switch', switch)
    do_delete(url)



def list_switches():
    """List all switches"""
    url = object_url('switches')
    do_get(url)



def port_register(switch, port):
    """Register a <port> with <switch> """
    url = object_url('switch', switch, 'port', port)
    do_put(url)



def port_delete(switch, port):
    """Delete a <port> from a <switch>"""
    url = object_url('switch', switch, 'port', port)
    do_delete(url)



def port_connect_nic(switch, port, node, nic):
    """Connect a <port> on a <switch> to a <nic> on a <node>"""
    url = object_url('switch', switch, 'port', port, 'connect_nic')
    do_post(url, data={'node': node, 'nic': nic})



def port_remove_nic(switch, port):
    """Detach a <port> on a <switch> from whatever's connected to it"""
    url = object_url('switch', switch, 'port', port, 'detach_nic')
    do_post(url)



def list_network_attachments(network, project):
    """List nodes connected to a network
    <project> may be either "all" or a specific project name.
    """
    url = object_url('network', network, 'attachments')

    if project == "all":
        do_get(url)
    else:
        do_get(url, params={'project': project})


#@cmd
def list_nodes(args):
    """List all nodes or all free nodes

    <is_free> may be either "all" or "free", and determines whether
        to list all nodes or all free nodes.
    """
    print "init list_nodes"
    if args.is_free not in ('all', 'free'):
        raise TypeError("is_free must be either 'all' or 'free'")
    print "init url"
    print args.is_free
    url = object_url('nodes', args.is_free)
    print url
    do_get(url)



def list_project_nodes(args):
    """List all nodes attached to a <project>"""
    url = object_url('project', args.project, 'nodes')
    do_get(url)



def list_project_networks(project):
    """List all networks attached to a <project>"""
    url = object_url('project', project, 'networks')
    do_get(url)



def show_switch(switch):
    """Display information about <switch>"""
    url = object_url('switch', switch)
    do_get(url)



def list_networks():
    """List all networks"""
    url = object_url('networks')
    do_get(url)



def show_network(network):
    """Display information about <network>"""
    url = object_url('network', network)
    do_get(url)



def show_node(node):
    """Display information about a <node>"""
    url = object_url('node', node)
    do_get(url)



def list_project_headnodes(project):
    """List all headnodes attached to a <project>"""
    url = object_url('project', project, 'headnodes')
    do_get(url)



def show_headnode(headnode):
    """Display information about a <headnode>"""
    url = object_url('headnode', headnode)
    do_get(url)



def list_headnode_images():
    """Display registered headnode images"""
    url = object_url('headnode_images')
    do_get(url)



def show_console(node):
    """Display console log for <node>"""
    url = object_url('node', node, 'console')
    do_get(url)



def start_console(node):
    """Start logging console output from <node>"""
    url = object_url('node', node, 'console')
    do_put(url)



def stop_console(node):
    """Stop logging console output from <node> and delete the log"""
    url = object_url('node', node, 'console')
    do_delete(url)



def create_admin_user(username, password):
    """Create an admin user. Only valid for the database auth backend.

    This must be run on the HaaS API server, with access to haas.cfg and the
    database. It will create an user named <username> with password
    <password>, who will have administrator priviledges.

    This command should only be used for bootstrapping the system; once you
    have an initial admin, you can (and should) create additional users via
    the API.
    """
    if not config.cfg.has_option('extensions', 'haas.ext.auth.database'):
        sys.exit("'make_inital_admin' is only valid with the database auth"
                 " backend.")
    from haas import model
    from haas.model import db
    from haas.ext.auth.database import User
    model.init_db()
    db.session.add(User(label=username, password=password, is_admin=True))
    db.session.commit()



def help(*commands):
    """Display usage of all following <commands>, or of all commands if none
    are given
    """
    if not commands:
        sys.stdout.write('Usage: %s <command> <arguments...> \n' % sys.argv[0])
        sys.stdout.write('Where <command> is one of:\n')
        commands = sorted(command_dict.keys())
    for name in commands:
        # For each command, print out a summary including the name, arguments,
        # and the docstring (as a #comment).
        sys.stdout.write('  %s\n' % usage_dict[name])
        sys.stdout.write('      %s\n' % command_dict[name].__doc__)


def main():
    """Entry point to the CLI.

    There is a script located at ${source_tree}/scripts/haas, which invokes
    this function.
    """
    print "config setting up"
    config.setup()
    print "config is setup"
    # TODO find a better place to put this
    # setup_http_client()
    print "cmdlistener running"
    setup_http_client()
    try:
        CommandListener()
    except FailedAPICallException:
        sys.exit(1)
    except InvalidAPIArgumentsException:
        sys.exit(2)
    '''if len(sys.argv) < 2 or sys.argv[1] not in command_dict:
        #Display usage for all commands
        help()
        sys.exit(1)
    else:
        setup_http_client()
        try:
            command_dict[sys.argv[1]](*sys.argv[2:])
        except FailedAPICallException:
            sys.exit(1)
        except InvalidAPIArgumentsException:
           sys.exit(2)'''
