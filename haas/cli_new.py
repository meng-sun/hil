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

from functools import wraps

command_dict = {}
usage_dict = {}
MIN_PORT_NUMBER = 1
MAX_PORT_NUMBER = 2**16 - 1


def set_func(function):
    """An argparser action class.
    Allows optional flags to set a default function"""

    class func_caller(argparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            super(func_caller, self).__init__(option_strings,
                                              dest, nargs, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, 'func', function)
            setattr(namespace, self.dest, values)
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


class ArgumentParserWithLongHelp(argparse.ArgumentParser):
    """ArgumentParser that prints a reformatted version
    of the usage statement when the user inputs too few
    arguments"""
    def __init__(self, prog=None, usage=None, **kwargs):
        super(ArgumentParserWithLongHelp, self).__init__(prog, usage, **kwargs)

    def error(self, message):
        args = {'prog': self.prog, 'message': message}
        if message == "too few arguments":
            command_string = self.format_usage()
            i = 0
            while i < len(command_string) and command_string[i] != ']':
                i += 1
            i += 1
            super(ArgumentParserWithLongHelp, self)._print_message(
                  "You entered: "+command_string[7:i]+"\n")
            super(ArgumentParserWithLongHelp, self)._print_message(
                  "Please check if missing: "+command_string[i:])
            super(ArgumentParserWithLongHelp, self).exit(
                  2, ('%(prog)s: error: %(message)s\n') % args)
        else:
            self.print_usage(sys.stderr)
            super(ArgumentParserWithLongHelp, self).exit(
                  2, ('%(prog)s: error: %(message)s\n') % args)


class CommandListener(object):
    """Creates argparse parser structure for calling API functions.
    Class variables are abstract parent parsers, and object variables
    hold all the subparsers passed between functions for sub-
    command creation. Calling self.run() will parse one user-input
    string.
    """
    get_name = argparse.ArgumentParser(add_help=False)
    get_name.add_argument('name', metavar='<object name>')

    get_type = argparse.ArgumentParser(add_help=False)
    get_type.add_argument('type', metavar='<object type>')

    def __init__(self):
        self.parser = ArgumentParserWithLongHelp('haas')
        self.subcommand_parsers = self.parser.add_subparsers()
        self.node_subparsers = None
        self.network_subparsers = None
        self.user_subparsers = None
        self.project_subparsers = None
        self.switch_subparsers = None
        self.port_subparsers = None
        self.headnode_subparsers = None
        self.nic_subparsers = None
        self.hnic_subparsers = None

    def run(self):
        """Creates all parsers and parses arguments.
        """
        self.serve_func()
        self.serve_networks_func()
        self.create_first_admin_func()
        self.node_func()
        self.network_func()
        self.user_func()
        self.project_func()
        self.switch_func()
        self.port_func()
        self.headnode_func()
        self.nic_func()
        self.hnic_func()

        args = self.parser.parse_args(sys.argv[1:])
        try:
            args.func(args)
        except TypeError:
            # any errors throw here are issues in the parser namespace
            print "Argument Type Not Accepted"
            raise InvalidAPIArgumentsException()

    def serve_func(self):
        serve_parser = self.subcommand_parsers.add_parser(
                       'serve', help="starts a http client")
        serve_parser.add_argument('port', type=int, help="port number")
        serve_parser.set_defaults(func=serve)

    def serve_networks_func(self):
        serve_networks_parser = self.subcommand_parsers.add_parser(
                                'serveNetworks')
        serve_networks_parser.set_defaults(func=serve_networks)

    def create_first_admin_func(self):
        create_first_admin = self.subcommand_parsers.add_parser('admin')
        create_first_admin.add_argument('name')
        create_first_admin.add_argument('password')
        create_first_admin.set_defaults(func=create_admin_user)

    def node_func(self):
        node_parser = self.subcommand_parsers.add_parser('node')
        self.node_subparsers = node_parser.add_subparsers()
        self.node_register_func()
        self.node_delete_func()
        self.node_disconnect_func()
        self.node_connect_func()
        self.node_show_func()
        self.node_list_func()
        self.node_console_func()
        self.node_power_func()

    def network_func(self):
        network_parser = self.subcommand_parsers.add_parser('network')
        self.network_subparsers = network_parser.add_subparsers()
        self.network_register_func()
        self.network_delete_func()
        self.network_show_func()
        self.network_list_func()
        self.network_connect_func()
        self.network_disconnect_func()

    def user_func(self):
        user_parser = self.subcommand_parsers.add_parser('user')
        self.user_subparsers = user_parser.add_subparsers()
        self.user_register_func()
        self.user_delete_func()
        self.user_connect_func()
        self.user_disconnect_func()

    def project_func(self):
        project_parser = self.subcommand_parsers.add_parser('project')
        self.project_subparsers = project_parser.add_subparsers()
        self.project_register_func()
        self.project_delete_func()
        self.project_disconnect_func()
        self.project_connect_func()

    def switch_func(self):
        switch_parser = self.subcommand_parsers.add_parser('switch')
        self.switch_subparsers = switch_parser.add_subparsers()
        self.switch_register_func()
        self.switch_delete_func()
        self.switch_show_func()
        self.switch_list_func()

    def headnode_func(self):
        headnode_parser = self.subcommand_parsers.add_parser('headnode')
        self.headnode_subparsers = headnode_parser.add_subparsers()
        self.headnode_register_func()
        self.headnode_delete_func()
        self.headnode_connect_func()
        self.headnode_detach_func()
        self.headnode_start_func()
        self.headnode_stop_func()
        self.headnode_show_func()
        self.headnode_list_func()
        self.headnode_images_func()

    def nic_func(self):
        nic_parser = self.subcommand_parsers.add_parser('nic')
        self.nic_subparsers = nic_parser.add_subparsers()
        self.nic_register_func()
        self.nic_delete_func()
        self.nic_connect_func()
        self.nic_disconnect_func()

    def hnic_func(self):
        hnic_parser = self.subcommand_parsers.add_parser('hnic')
        self.hnic_subparsers = hnic_parser.add_subparsers()
        self.hnic_register_func()
        self.hnic_delete_func()

    def port_func(self):
        port_parser = self.subcommand_parsers.add_parser('port')
        self.port_subparsers = port_parser.add_subparsers()
        self.port_register_func()
        self.port_delete_func()
        self.port_disconnect_func()
        self.port_connect_func()

    def node_register_func(self):
        node_reg_parser = self.node_subparsers.add_parser(
                               'register', parents=[CommandListener.get_name])
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
        node_reg_parser.set_defaults(func=node_register)

    def node_delete_func(self):
        node_delete_parser = self.node_subparsers.add_parser(
                             'delete', parents=[CommandListener.get_name])
        node_delete_parser.set_defaults(func=node_delete)

    def node_disconnect_func(self):
        node_disconnect = self.node_subparsers.add_parser(
                          'disconnect', parents=[CommandListener.get_name])
        node_disconnects = node_disconnect.add_mutually_exclusive_group(
                           required=True)
        node_disconnects.add_argument('--network',
                                      action=set_func(node_remove_network),
                                      nargs=2,
                                      metavar=('<network name>', '<nic name>')
                                      )
        node_disconnects.add_argument('--project', metavar='<project name>',
                                      action=set_func(project_remove_node))
        node_disconnect.set_defaults(func=empty)

    def node_connect_func(self):
        node_connect = self.node_subparsers.add_parser(
                       'connect', parents=[CommandListener.get_name])
        node_connects = node_connect.add_mutually_exclusive_group(
                        required=True)
        node_connects.add_argument('--network',
                                   action=set_func(node_connect_network),
                                   nargs=2,
                                   metavar=('<network name>', '<nic name>')
                                   )

        node_connects.add_argument('--project', metavar='<project name>',
                                   action=set_func(project_connect_node))

    def node_show_func(self):
        node_show = self.node_subparsers.add_parser(
                    'show', parents=[CommandListener.get_name])
        node_show.set_defaults(func=show_node)

    def node_list_func(self):
        node_list = self.node_subparsers.add_parser('list')
        node_lists = node_list.add_mutually_exclusive_group(required=True)
        node_lists.add_argument('--project', '-proj',
                                action=set_func(list_project_nodes))
        node_lists.add_argument('--network', '-net', nargs=2,
                                metavar=('<network name>',
                                         '<project name> or all'),
                                action=set_func(list_network_attachments))
        node_lists.add_argument('--free', dest='is_free', action='store_true')
        node_lists.add_argument('--all', dest='is_free', action='store_false')
        node_list.set_defaults(func=list_nodes)

    def node_power_func(self):
        node_power = self.node_subparsers.add_parser('power')
        node_powers = node_power.add_subparsers()
        node_powers_off = node_powers.add_parser(
                          'off', parents=[CommandListener.get_name])
        node_powers_off.set_defaults(func=node_power_off)
        node_powers_cycle = node_powers.add_parser(
                            'cycle', parents=[CommandListener.get_name])
        node_powers_cycle.set_defaults(func=node_power_cycle)

    def node_console_func(self):
        node_console = self.node_subparsers.add_parser('console')
        node_console_actions = node_console.add_subparsers()
        node_console_show = node_console_actions.add_parser(
                            'show', parents=[CommandListener.get_name])
        node_console_show.set_defaults(func=show_console)
        node_console_start = node_console_actions.add_parser(
                             'start', parents=[CommandListener.get_name])
        node_console_start.set_defaults(func=start_console)
        node_console_stop = node_console_actions.add_parser(
                            'stop', parents=[CommandListener.get_name])
        node_console_stop.set_defaults(func=stop_console)

    def user_register_func(self):
        user_reg = self.user_subparsers.add_parser(
                   'register', parents=[CommandListener.get_name])
        user_reg.set_defaults(func=user_create)
        user_reg.add_argument('--password', '--pass')
        user_reg.add_argument('--admin', action='store_true')

    def user_delete_func(self):
        user_del = self.user_subparsers.add_parser(
                   'delete', parents=[CommandListener.get_name])
        user_del.set_defaults(func=user_delete)

    def user_connect_func(self):
        user_con = self.user_subparsers.add_parser(
                   'connect', parents=[CommandListener.get_name])
        user_con.set_defaults(func=user_add_project)
        user_con.add_argument('--project', '--proj')

    def user_disconnect_func(self):
        user_dis = self.user_subparsers.add_parser(
                   'disconnect', parents=[CommandListener.get_name])
        user_dis.set_defaults(func=user_remove_project)
        user_dis.add_argument('--project', '--proj')

    def headnode_register_func(self):
        hn_reg = self.headnode_subparsers.add_parser(
                 'register', parents=[CommandListener.get_name])
        hn_reg.add_argument('--project', '--proj', required=True)
        hn_reg.add_argument('--image', '--img',
                            choices=['img1', 'img2', 'img3', 'img4'],
                            required=True)
        hn_reg.set_defaults(func=headnode_create)

    def headnode_delete_func(self):
        hn_delete = self.headnode_subparsers.add_parser(
                    'delete', parents=[CommandListener.get_name])
        hn_delete.set_defaults(func=headnode_delete)

    def headnode_connect_func(self):
        hn_connect = self.headnode_subparsers.add_parser(
                     'connect', parents=[CommandListener.get_name])
        hn_connect.add_argument('--network', required=True)
        hn_connect.add_argument('--hnic', required=True)
        hn_connect.set_defaults(func=headnode_connect_network)

    def headnode_detach_func(self):
        hn_detach = self.headnode_subparsers.add_parser(
                    'disconnect', parents=[CommandListener.get_name])
        hn_detach.add_argument('---hnic', required=True)
        hn_detach.set_defaults(func=headnode_remove_network)

    def headnode_start_func(self):
        hn_start = self.headnode_subparsers.add_parser(
                   'start', parents=[CommandListener.get_name])
        hn_start.set_defaults(func=headnode_start)

    def headnode_stop_func(self):
        hn_stop = self.headnode_subparsers.add_parser(
                  'stop', parents=[CommandListener.get_name])
        hn_stop.set_defaults(func=headnode_stop)

    def headnode_show_func(self):
        show_hn = self.headnode_subparsers.add_parser(
                  'show', parents=[CommandListener.get_name])
        show_hn.set_defaults(func=show_headnode)

    def headnode_list_func(self):
        list_hn = self.headnode_subparsers.add_parser('list')
        list_hn.add_argument('--project', '-proj', required=True)
        list_hn.set_defaults(func=list_project_headnodes)

    def headnode_images_func(self):
        hn_images = self.headnode_subparsers.add_parser('images')
        hn_images.set_defaults(func=list_headnode_images)

    def nic_register_func(self):
        nic_register = self.nic_subparsers.add_parser(
                       'register', parents=[CommandListener.get_name])
        nic_register.set_defaults(func=node_register_nic)
        nic_register.add_argument('--node', required=True)
        nic_register.add_argument('--macaddr', required=True)

    def nic_delete_func(self):
        nic_delete = self.nic_subparsers.add_parser(
                     'delete', parents=[CommandListener.get_name])
        nic_delete.set_defaults(func=node_delete_nic)
        nic_delete.add_argument('--node', required=True)

    def nic_connect_func(self):
        nic_connect = self.nic_subparsers.add_parser(
                      'connect', parents=[CommandListener.get_name])
        nic_connect.set_defaults(func=port_connect_nic)
        nic_connect.add_argument('--node', required=True)
        nic_connect.add_argument('--switch', required=True)
        nic_connect.add_argument('--port', required=True)

    def nic_disconnect_func(self):
        nic_disconnect = self.nic_subparsers.add_parser('disconnect')
        nic_disconnect.set_defaults(func=port_remove_nic)
        nic_disconnect.add_argument('--port', required=True)
        nic_disconnect.add_argument('--switch', required=True)

    def hnic_register_func(self):
        hnic_register = self.hnic_subparsers.add_parser(
                        'register', parents=[CommandListener.get_name])
        hnic_register.set_defaults(func=headnode_create_hnic)
        hnic_register.add_argument('--headnode', required=True)

    def hnic_delete_func(self):
        hnic_delete = self.hnic_subparsers.add_parser(
                      'delete', parents=[CommandListener.get_name])
        hnic_delete.set_defaults(func=headnode_delete_hnic)
        hnic_delete.add_argument('--headnode', required=True)

    def port_register_func(self):
        port_register_parser = self.port_subparsers.add_parser(
                               'register', parents=[CommandListener.get_name])
        port_register_parser.add_argument('--switch', required=True)
        port_register_parser.set_defaults(func=port_register)

    def port_delete_func(self):
        port_delete_parser = self.port_subparsers.add_parser(
                             'delete', parents=[CommandListener.get_name])
        port_delete_parser.set_defaults(func=port_delete)
        port_delete_parser.add_argument('--switch', required=True)

    def port_disconnect_func(self):
        port_disconnect = self.port_subparsers.add_parser(
                          'disconnect', parents=[CommandListener.get_name])
        port_disconnect.add_argument('--switch', required=True)
        port_disconnect.set_defaults(func=port_remove_nic)

    def port_connect_func(self):
        port_connect = self.port_subparsers.add_parser(
                       'connect', parents=[CommandListener.get_name])
        port_connect.set_defaults(func=port_connect_nic)
        port_connect.add_argument('--switch', required=True)
        port_connect.add_argument('--node', required=True)
        port_connect.add_argument('--nic', required=True)

    def network_register_func(self):
        net_create = self.network_subparsers.add_parser(
                     'register', parents=[CommandListener.get_name])
        net_create.set_defaults(func=network_create)
        net_creates = net_create.add_mutually_exclusive_group(required=True)
        net_creates.add_argument('--description', nargs=3,
                                 metavar=('<owner>', '<access>', '<net id>'))
        net_creates.add_argument('--simple', metavar='<project name>',
                                 action=set_func(network_create_simple),
                                 dest='project')

    def network_delete_func(self):
        net_delete = self.network_subparsers.add_parser(
                     'delete', parents=[CommandListener.get_name])
        net_delete.set_defaults(func=network_delete)

    def network_show_func(self):
        net_show = self.network_subparsers.add_parser(
                   'show', parents=[CommandListener.get_name])
        net_show.set_defaults(func=show_network)

    def network_list_func(self):
        net_list = self.network_subparsers.add_parser('list')
        net_list.set_defaults(func=list_networks)
        net_lists = net_list.add_mutually_exclusive_group()
        net_lists.add_argument('--project', '--proj',
                               action=set_func(list_project_networks))
        net_lists.add_argument('--attachments', nargs=2,
                               metavar=('<project name> or all',
                                        '<network name>'),
                               action=set_func(list_network_attachments))

    def network_connect_func(self):
        net_connect = self.network_subparsers.add_parser(
                      'connect', parents=[CommandListener.get_name])
        net_connect.add_argument(
            '--headnode', '--hnode',
            action=set_func(headnode_connect_network))
        net_connect.add_argument('--hnic')
        net_connect.add_argument(
            '--node', action=set_func(node_connect_network))
        net_connect.add_argument(
            '--project', '--proj',
            action=set_func(network_grant_project_access))

    def network_disconnect_func(self):
        net_dis = self.network_subparsers.add_parser(
                  'disconnect', parents=[CommandListener.get_name])
        net_dis.add_argument('--project', '--proj',
                             action=set_func(network_remove_project))
        net_dis.add_argument('--headnode', '--hnode',
                             action=set_func(node_remove_network))
        net_dis.add_argument('--hnic')
        net_dis.add_argument('--node',
                             action=set_func(headnode_remove_network))
        net_dis.add_argument('--nic')

    def project_register_func(self):
        proj_create = self.project_subparsers.add_parser(
                      'register', parents=[CommandListener.get_name])
        proj_create.set_defaults(func=project_create)

    def project_delete_func(self):
        proj_delete = self.project_subparsers.add_parser(
                      'delete', parents=[CommandListener.get_name])
        proj_delete.set_defaults(func=project_delete)

    def project_connect_func(self):
        proj_connect = self.project_subparsers.add_parser(
                       'connect', parents=[CommandListener.get_name])
        proj_connect.add_argument('--node',
                                  action=set_func(project_connect_node))
        proj_connect.add_argument('--network', '--net', action=set_func(
                                  network_grant_project_access))
        proj_connect.add_argument('--user', action=set_func(user_add_project))

    def project_disconnect_func(self):
        proj_dis = self.project_subparsers.add_parser(
                   'disconnect', parents=[CommandListener.get_name])
        proj_dis.add_argument('--user', action=set_func(user_remove_project))
        proj_dis.add_argument('--network', '--net',
                              action=set_func(network_remove_project))
        proj_dis.add_argument('--project', '--proj',
                              action=set_func(project_remove_node))
        proj_dis.add_argument('--node', action=set_func(project_remove_node))

    def project_list_func(self):
        proj_list = self.project_subparsers.add_parser('list')
        proj_list.set_defaults(func=list_projects)

    def switch_register_func(self):
        switch_register_parser = self.switch_subparsers.add_parser(
                                 'register',
                                 parents=[CommandListener.get_name])
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
        switch_register_parser.set_defaults(func=switch_register)

    def switch_delete_func(self):
        switch_delete_parser = self.switch_subparsers.add_parser(
                               'delete', parents=[CommandListener.get_name])
        switch_delete_parser.set_defaults(func=switch_delete)

    def switch_show_func(self):
        switch_show = self.switch_subparsers.add_parser(
                      'show', parents=[CommandListener.get_name])
        switch_show.set_defaults(func=show_switch)

    def switch_list_func(self):
        switch_list = self.switch_subparsers.add_parser('list')
        switch_list.set_defaults(func=list_switches)


def serve(args):
    try:
        args.port = schema.And(schema.Use(int),
                               lambda n:
                               MIN_PORT_NUMBER <= n <= MAX_PORT_NUMBER
                               ).validate(args.port)
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


def serve_networks(args):
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
    if args.admin:
        is_admin = "admin"
    else:
        is_admin = "regular"

    url = object_url('/auth/basic/user', args.name)
    do_put(url, data={
        'password': args.password,
        'is_admin': is_admin,
    })


def network_create(args):
    """Create a link-layer <network>. See docs/networks.md for details."""
    network = args.name
    owner = args.description[0]
    access = args.description[1]
    net_id = args.description[2]
    url = object_url('network', network)
    do_put(url, data={'owner': owner,
                      'access': access,
                      'net_id': net_id})


def network_create_simple(args):
    """Creates a simple <network> owned by project."""
    url = object_url('network', args.name)
    do_put(url, data={'owner': args.project,
                      'access': args.project,
                      'net_id': ""})


def network_delete(args):
    """Delete a <network>"""
    network = args.name
    url = object_url('network', network)
    do_delete(url)


def user_delete(args):
    """Delete the user <username>"""
    url = object_url('/auth/basic/user', args.name)
    do_delete(url)


def list_projects(args):
    """List all projects"""
    url = object_url('projects')
    do_get(url)


def user_add_project(args):
    """Add <user> to <project>"""
    if hasattr(args, 'user'):
        user = args.user
        project = args.name
    else:
        user = args.name
        project = args.project
    url = object_url('/auth/basic/user', user, 'add_project')
    do_post(url, data={'project': project})


def user_remove_project(args):
    """Remove <user> from <project>"""
    if hasattr(args, 'user'):
        user = args.user
        project = args.name
    else:
        user = args.name
        project = args.project
    url = object_url('/auth/basic/user', user, 'remove_project')
    do_post(url, data={'project': project})


def network_grant_project_access(args):
    """Add <project> to <network> access"""
    if hasattr(args, 'network'):
        network = args.network
        project = args.name
    else:
        network = args.name
        project = args.project
    url = object_url('network', network, 'access', project)
    do_put(url)


def network_remove_project(args):
    """Remove <project> from <network> access"""
    if hasattr(args, 'network'):
        network = args.name
        project = args.project
    else:
        network = args.network
        project = args.name
    url = object_url('network', network, 'access', project)
    do_delete(url)


def project_create(args):
    """Create a <project>"""
    url = object_url('project', args.name)
    do_put(url)


def project_delete(args):
    """Delete <project>"""
    url = object_url('project', args.name)
    do_delete(url)


def headnode_create(args):
    """Create a <headnode> in a <project> with <base_img>"""
    headnode = args.name
    project = args.project
    base_img = args.image
    url = object_url('headnode', headnode)
    do_put(url, data={'project': project,
                      'base_img': base_img})


def headnode_delete(args):
    """Delete <headnode>"""
    headnode = args.name
    url = object_url('headnode', headnode)
    do_delete(url)


def project_connect_node(args):
    """Connect <node> to <project>"""
    if hasattr(args, 'project'):
        node = args.name
        project = args.project
    else:
        node = args.node
        project = args.name
    url = object_url('project', project, 'connect_node')
    do_post(url, data={'node': node})


def project_remove_node(args):
    """Detach <node> from <project>"""
    if hasattr(args, 'project'):
        node = args.name
        project = args.project
    else:
        node = args.node
        project = args.name
    url = object_url('project', project, 'detach_node')
    do_post(url, data={'node': node})


def headnode_start(args):
    """Start <headnode>"""
    headnode = args.name
    url = object_url('headnode', headnode, 'start')
    do_post(url)


def headnode_stop(args):
    """Stop <headnode>"""
    headnode = args.name
    url = object_url('headnode', headnode, 'stop')
    do_post(url)


def empty(args):
    """used to prevent argparse from throwing func not found
    errors if the user forgets to include a option flag"""
    pass


def node_register(args):
    """Register a node named <node>, with the given type
        if obm is of type: ipmi then provide arguments
        "ipmi", <hostname>, <ipmi-username>, <ipmi-password>
    """
    obm_api = "http://schema.massopencloud.org/haas/v0/obm/"
    obm_types = ["ipmi", "mock"]
    for obm in obm_types:
        if hasattr(args, obm):
            subtype = obm

    details = getattr(args, subtype)
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


def node_delete(args):
    """Delete <node>"""
    url = object_url('node', args.name)
    do_delete(url)


def node_power_cycle(args):
    """Power cycle <node>"""
    url = object_url('node', args.name, 'power_cycle')
    do_post(url)


def node_power_off(args):
    """Power off <node>"""
    url = object_url('node', args.name, 'power_off')
    do_post(url)


def node_register_nic(args):
    """
    Register existence of a <nic> with the given <macaddr> on the given <node>
    """
    nic = args.name
    node = args.node
    macaddr = args.macaddr
    url = object_url('node', node, 'nic', nic)
    do_put(url, data={'macaddr': macaddr})


def node_delete_nic(args):
    """Delete a <nic> on a <node>"""
    node = args.node
    nic = args.name
    url = object_url('node', node, 'nic', nic)
    do_delete(url)


def headnode_create_hnic(args):
    """Create a <nic> on the given <headnode>"""
    headnode = args.headnode
    nic = args.name
    url = object_url('headnode', headnode, 'hnic', nic)
    do_put(url)


def headnode_delete_hnic(args):
    """Delete a <nic> on a <headnode>"""
    headnode = args.headnode
    nic = args.name
    url = object_url('headnode', headnode, 'hnic', nic)
    do_delete(url)


def node_connect_network(args):
    """Connect <node> to <network> on given <nic> and <channel>"""
    if hasattr(args, 'network'):
        node = args.name
        nic = args.network[1]
        network = args.network[0]
    else:
        node = args.node[0]
        nic = args.node[1]
        network = args.name
    url = object_url('node', node, 'nic', nic, 'connect_network')
    do_post(url, data={'network': network,
                       'channel': channel})


def node_remove_network(args):
    """Detach <node> from the given <network> on the given <nic>"""
    if hasattr(args, 'network'):
        node = args.name
        nic = args.network[1]
        network = args.network[0]
    else:
        node = args.node[0]
        nic = args.node[1]
        network = args.name
    url = object_url('node', node, 'nic', nic, 'detach_network')
    do_post(url, data={'network': network})


def headnode_connect_network(args):
    """Connect <headnode> to <network> on given <nic>"""
    if hasattr(args, 'network'):
        headnode = args.headnode
        hnic = args.hnic
        network = args.name
    else:
        headnode = args.name
        hnic = args.hnic
        network = args.network
    url = object_url('headnode', headnode, 'hnic', nic, 'connect_network')
    do_post(url, data={'network': network})


def headnode_remove_network(args):
    """Detach <headnode> from the network on given <nic>"""
    if hasattr(args, 'network'):
        headnode = args.headnode
        hnic = args.hnic
    else:
        headnode = args.name
        hnic = args.hnic
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
    for sub_type in ["nexus", "mock", "powerconnect55xx", "brocade"]:
        if getattr(org_args, sub_type) is not None:
            args = getattr(org_args, sub_type)
            subtype = sub_type

    switch = org_args.name
    switch_api = "http://schema.massopencloud.org/haas/v0/switches/"

    if subtype == "nexus":
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
        if len(args) == 3:
            switchinfo = {"type": switch_api + subtype, "hostname": args[0],
                          "username": args[1], "password": args[2]}
        else:
            sys.stderr.write('ERROR: subtype ' + subtype +
                             ' requires exactly 3 arguments\n')
            sys.stderr.write('<hostname> <username> <password>\n')
            return
    elif subtype == "powerconnect55xx":
        if len(args) == 3:
            switchinfo = {"type": switch_api + subtype, "hostname": args[0],
                          "username": args[1], "password": args[2]}
        else:
            sys.stderr.write(_('ERROR: subtype ' + subtype +
                               ' requires exactly 3 arguments\n'
                               '<hostname> <username> <password>\n'))
            return
    elif subtype == "brocade":
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


def switch_delete(args):
    """Delete a <switch> """
    switch = args.name
    url = object_url('switch', switch)
    do_delete(url)


def list_switches(args):
    """List all switches"""
    url = object_url('switches')
    do_get(url)


def port_register(args):
    """Register a <port> with <switch> """
    switch = args.switch
    port = args.name
    url = object_url('switch', switch, 'port', port)
    do_put(url)


def port_delete(args):
    """Delete a <port> from a <switch>"""
    port = args.name
    switch = args.switch
    url = object_url('switch', switch, 'port', port)
    do_delete(url)


def port_connect_nic(args):
    """Connect a <port> on a <switch> to a <nic> on a <node>"""
    if hasattr(args, 'port'):
        switch = args.switch
        port = args.port
        node = args.node
        nic = args.name
    else:
        switch = args.switch
        port = args.name
        node = args.node
        nic = args.nic
    url = object_url('switch', switch, 'port', port, 'connect_nic')
    do_post(url, data={'node': node, 'nic': nic})


def port_remove_nic(args):
    """Detach a <port> on a <switch> from whatever's connected to it"""
    switch = args.switch
    if hasattr(args, 'port'):
        port = args.port
    else:
        port = args.name
    url = object_url('switch', switch, 'port', port, 'detach_nic')
    do_post(url)


def list_network_attachments(args):
    """List nodes connected to a network
    <project> may be either "all" or a specific project name.
    """
    if hasattr(args, 'network'):
        network = args.network[0]
        project = args.network[1]
    else:
        network = args.attachments[1]
        project = args.attachments[0]
    url = object_url('network', network, 'attachments')

    if project == "all":
        do_get(url)
    else:
        do_get(url, params={'project': project})


def list_nodes(args):
    """List all nodes or all free nodes
    <is_free> may be either "all" or "free", and determines whether
        to list all nodes or all free nodes.
    """
    if args.is_free:
        is_free = 'free'
    else:
        is_free = 'all'
    url = object_url('nodes', is_free)
    do_get(url)


def list_project_nodes(args):
    """List all nodes attached to a <project>"""
    url = object_url('project', args.project, 'nodes')
    do_get(url)


def list_project_networks(args):
    """List all networks attached to a <project>"""
    project = args.project
    url = object_url('project', project, 'networks')
    do_get(url)


def show_switch(args):
    """Display information about <switch>"""
    url = object_url('switch', args.name)
    do_get(url)


def list_networks(args):
    """List all networks"""
    url = object_url('networks')
    do_get(url)


def show_network(args):
    """Display information about <network>"""
    network = args.name
    url = object_url('network', network)
    do_get(url)


def show_node(args):
    """Display information about a <node>"""
    url = object_url('node', args.name)
    do_get(url)


def list_project_headnodes(args):
    """List all headnodes attached to a <project>"""
    project = args.project
    url = object_url('project', project, 'headnodes')
    do_get(url)


def show_headnode(args):
    """Display information about a <headnode>"""
    headnode = args.name
    url = object_url('headnode', headnode)
    do_get(url)


def list_headnode_images(args):
    """Display registered headnode images"""
    url = object_url('headnode_images')
    do_get(url)


def show_console(args):
    """Display console log for <node>"""
    node = args.name
    url = object_url('node', node, 'console')
    do_get(url)


def start_console(args):
    """Start logging console output from <node>"""
    node = args.name
    url = object_url('node', node, 'console')
    do_put(url)


def stop_console(args):
    node = args.name
    """Stop logging console output from <node> and delete the log"""
    url = object_url('node', node, 'console')
    do_delete(url)


def create_admin_user(args):
    """Create an admin user. Only valid for the database auth backend.

    This must be run on the HaaS API server, with access to haas.cfg and the
    database. It will create an user named <username> with password
    <password>, who will have administrator priviledges.

    This command should only be used for bootstrapping the system; once you
    have an initial admin, you can (and should) create additional users via
    the API.
    """
    username = args.name
    password = args.password
    if not config.cfg.has_option('extensions', 'haas.ext.auth.database'):
        sys.exit("'make_inital_admin' is only valid with the database auth"
                 " backend.")
    from haas import model
    from haas.model import db
    from haas.ext.auth.database import User
    model.init_db()
    db.session.add(User(label=username, password=password, is_admin=True))
    db.session.commit()


def main():
    """Entry point to the CLI.

    There is a script located at ${source_tree}/scripts/haas, which invokes
    this function.
    """
    config.setup()
    setup_http_client()
    try:
        CommandListener().run()
    except FailedAPICallException:
        sys.exit(1)
    except InvalidAPIArgumentsException:
        sys.exit(2)
