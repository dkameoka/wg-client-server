#!/usr/bin/env python3

# pylint: disable=broad-except,missing-function-docstring
# pylint: disable=missing-module-docstring,too-many-instance-attributes

import argparse
import secrets
import csv
import shutil
import ipaddress
import base64
import binascii
from subprocess import Popen, run, PIPE
from pathlib import Path
from dataclasses import dataclass


@dataclass
class _Server:
    """ Server info """
    ipa: ipaddress.IPv6Address
    net: ipaddress.IPv6Network
    name: str
    prefix: str
    endpoint: str
    listenport: str
    privatekey: str
    publickey: str
    table: str
    preup: str
    postup: str
    predown: str
    postdown: str


@dataclass
class _Client:
    """ Client info """
    ipa: ipaddress.IPv6Address
    net: ipaddress.IPv6Network
    name: str
    allowedip: str
    persistentkeepalive: str  # Needed by clients behind a NAT
    privatekey: str
    publickey: str
    presharedkey: str


class ValueExc(Exception):
    """ Raised when value is invalid """


class WireguardClientServer:
    """ Generates client server configurations """

    def __init__(self, wireguard_path, qrencode_path, server_path, client_path):
        self.wireguard_path = wireguard_path
        self.qrencode_path = qrencode_path
        self.servers = []
        self.clients = []
        self.server_csv(server_path)
        self.client_csv(client_path)

    def server_csv(self, path):
        with path.open('r', newline='') as file:
            fieldnames = ('name', 'prefix', 'endpoint', 'listenport', 'privatekey', 'table',
                          'preup', 'postup', 'predown', 'postdown')
            reader = csv.DictReader(
                file, fieldnames=fieldnames, delimiter=',', quotechar='"', restval='')
            for row in reader:
                try:
                    self.server_row(row)
                except ValueExc as valexc:
                    print(f'{path} error: {valexc}')

    def server_row(self, row):
        self.validate_name(row['name'])
        self.validate_prefix(row, row['prefix'])
        self.validate_endpoint(row['endpoint'])
        self.validate_listenport(row['listenport'])
        self.validate_privatekey(row, row['privatekey'])
        self.validate_table(row['table'])
        self.servers += [_Server(**row)]

    def validate_name(self, name):
        for char in name:
            if not char.isalnum() and char not in ['_', '=', '+', '.', '-']:
                raise ValueExc(f'Name "{name}" has characters besides alpha-numerics and "_=+.-"')
        length = len(name)
        if length == 0 or length > 15:
            raise ValueExc(f'Name "{name}" is invalid or too long')
        for server in self.servers:
            if server.name == name:
                raise ValueExc(f'Name "{name}" is a duplicate of a server\'s name')
        for client in self.clients:
            if client.name == name:
                raise ValueExc(f'Name "{name}" is a duplicate of a client\'s name')

    def validate_key(self, key):
        try:
            decoded = base64.b64decode(key, validate=True)
            if len(decoded) != 32:
                raise ValueExc(f'Key "{key}" is not 32 bytes of base64')
        except binascii.Error as berr:
            raise ValueExc(f'Key "{key}" is not valid base64') from berr
        for server in self.servers:
            if key in [server.privatekey, server.publickey]:
                raise ValueExc(f'Key "{key}" is a duplicate of {server.name}\'s key')
        for client in self.clients:
            if key in [client.privatekey, client.publickey, client.presharedkey]:
                raise ValueExc(f'Key "{key}" is a duplicate of {client.name}\'s key')

    def validate_prefix(self, row, prefix):
        iface = ipaddress.IPv6Interface(prefix)
        if iface.network.prefixlen != 48:
            raise ValueExc(f'Prefix "{prefix}" prefix length should be 48')
        if not iface.ip.is_private:
            raise ValueExc(f'Prefix "{prefix}" is not a unique local address')
        for server in self.servers:
            if iface.network.overlaps(server.net):
                raise ValueExc(f'Prefix "{prefix}" with {str(iface.network)} overlaps with '
                               f'another server network {str(server.net)}')
        row['ipa'] = iface.ip
        row['net'] = iface.network

    def validate_endpoint(self, endpoint):
        endpoint_split = endpoint.split(':')
        if len(endpoint_split) != 2:
            raise ValueExc(f'Endpoint "{endpoint}" is invalid or is missing the port. '
                           f'Example: hostname_or_ip:443')
        self.validate_port(endpoint_split[1])

    @staticmethod
    def validate_port(port):
        try:
            port = int(port)
        except ValueError as valerr:
            raise ValueExc(f'Port "{port}" is not an integer') from valerr
        if port < 1 or port > 65535:
            raise ValueExc(f'Port "{port}" must be between 1 and 65535 inclusive')

    def validate_listenport(self, listenport):
        self.validate_port(listenport)

    def validate_privatekey(self, row, privatekey):
        self.validate_key(privatekey)
        with Popen([self.wireguard_path, 'pubkey'], stdout=PIPE, stdin=PIPE) as proc:
            public, _ = proc.communicate(privatekey.encode())
            if proc.returncode != 0:
                raise ValueExc(f'Could not generate public key for {row["name"]}:{privatekey}')
        row['publickey'] = public.decode().strip()

    @staticmethod
    def validate_table(table):
        if not table or len(table) == 0:
            return
        try:
            _ = int(table)
        except ValueError as valerr:
            if table.lower() in ['off', 'auto']:
                pass
            raise ValueExc(f'Table {table} is not "off", "auto", or an integer') from valerr

    def client_csv(self, path):
        with path.open('r', newline='') as file:
            fieldnames = ('name', 'allowedip', 'persistentkeepalive',
                          'privatekey', 'presharedkey')
            reader = csv.DictReader(
                file, fieldnames=fieldnames, delimiter=',', quotechar='"', restval='')
            for row in reader:
                try:
                    self.client_row(row)
                except ValueExc as valexc:
                    print(f'{path} error: {valexc}')

    def client_row(self, row):
        self.validate_name(row['name'])
        self.validate_allowedip(row, row['allowedip'])
        self.validate_persistentkeepalive(row['persistentkeepalive'])
        self.validate_privatekey(row, row['privatekey'])
        self.validate_key(row['presharedkey'])
        self.clients += [_Client(**row)]

    def validate_allowedip(self, row, allowedip):
        try:
            iface = ipaddress.IPv6Interface(allowedip)
        except ipaddress.AddressValueError as exc:
            raise ValueExc(f'AllowedIP "{allowedip}" is not valid: {exc}') from exc
        if iface.network.prefixlen != 64:
            raise ValueExc(f'AllowedIP "{allowedip}" with prefix length should be 64')
        if not iface.ip.is_private:
            raise ValueExc(f'AllowedIP "{allowedip}" is not a unique local address')
        for client in self.clients:
            if client.ipa == iface.ip:
                raise ValueExc(f'AllowedIP "{allowedip}" is a duplicate of {client.name}\'s')
        for server in self.servers:
            if server.ipa == iface.ip:
                raise ValueExc(f'AllowedIP "{allowedip}" is a duplicate of {server.name}\'s')
        for server in self.servers:
            if iface.ip in server.net:
                break
        else:
            raise ValueExc(f'AllowedIP "{allowedip}" has no matching server network')
        row['ipa'] = iface.ip
        row['net'] = iface.network

    @staticmethod
    def validate_persistentkeepalive(keepalive):
        try:
            keepalive_ = int(keepalive)
        except ValueError as valerr:
            raise ValueExc(f'Persistentkeepalive "{keepalive}" is not an integer') from valerr
        if keepalive_ < 1 or keepalive_ > 7200:
            raise ValueExc(f'Persistentkeepalive "{keepalive}" must be ' +
                           'between 1 and 7200 inclusive')

    @staticmethod
    def _write_if_different(outfile, contents):
        if outfile.exists() and outfile.read_text(encoding='UTF-8', errors='ignore') == contents:
            return False
        outfile.write_text(contents, encoding='UTF-8', errors='ignore', newline='\n')
        return True

    def server_output(self, outdir):
        for server in self.servers:
            output = '[Interface]\n'
            output += f'# ServerName = {server.name}\n'
            output += f'Address = {server.ipa}/{server.net.prefixlen}\n'
            output += f'ListenPort = {server.listenport}\n'
            output += f'PrivateKey = {server.privatekey}\n'
            if server.table and len(server.table) > 0:
                output += f'Table = {server.table}\n'
            if server.preup and len(server.preup) > 0:
                output += f'PreUp = {server.preup}\n'
            if server.postup and len(server.postup) > 0:
                output += f'PostUp = {server.postup}\n'
            if server.predown and len(server.predown) > 0:
                output += f'PreDown = {server.predown}\n'
            if server.postdown and len(server.postdown) > 0:
                output += f'PostDown = {server.postdown}\n'
            output += '\n'
            for client in self.clients:
                output += '[Peer]\n'
                output += f'# Name = {client.name}\n'
                output += f'PublicKey = {client.publickey}\n'
                output += f'PresharedKey = {client.presharedkey}\n'
                output += f'AllowedIPs = {client.ipa}/{client.net.max_prefixlen}\n'
            outpath = outdir / (server.name + '.conf')
            self._write_if_different(outpath, output)
            outpath.chmod(0o600)  # Try to use secure permissions.

    def _qrencode(self, filepath, outpng):
        if not self.qrencode_path:
            return
        try:
            run([self.qrencode_path, '-r', filepath, '-o', outpng], check=True)
            outpng.chmod(0o600)
        except Exception as exc:
            print(f'Qrencode error: {exc}')
            self.qrencode_path = None

    def client_output(self, outdir):
        for client in self.clients:
            for server in self.servers:
                if client.ipa not in server.net:
                    continue
                output = f'# ServerName = {server.name}\n\n'
                output += '[Interface]\n'
                output += f'# Name = {client.name}\n'
                output += f'Address = {client.ipa}/{client.net.max_prefixlen}\n'
                output += f'PrivateKey = {client.privatekey}\n\n'
                output += '[Peer]\n'
                output += f'# Name = {server.name}\n'
                output += f'AllowedIPs = {server.net}\n'
                output += f'Endpoint = {server.endpoint}\n'
                output += f'PublicKey = {server.publickey}\n'
                output += f'PresharedKey = {client.presharedkey}\n'
                output += f'PersistentKeepalive = {client.persistentkeepalive}\n'
                outpath = outdir / (client.name + '.conf')
                outpng = outpath.with_suffix('.png')
                if self._write_if_different(outpath, output) or not outpng.exists():
                    self._qrencode(outpath, outpng)
                outpath.chmod(0o600)  # Try to use secure permissions.
                break


def gen_privatekey(wireguard_path):
    with Popen([wireguard_path, 'genkey'], stdout=PIPE) as proc:
        private, _ = proc.communicate()
        if proc.returncode != 0:
            raise ValueExc('Could not generate private key')
    return private.decode().strip()


def gen_presharedkey(wireguard_path):
    with Popen([wireguard_path, 'genpsk'], stdout=PIPE) as proc:
        preshared, _ = proc.communicate()
        if proc.returncode != 0:
            raise ValueExc('Could not generate preshared key')
    return preshared.decode().strip()


def gen_ula():
    prefix_l = int('fd' + '0' * 30, 16)
    random = secrets.randbits(40) << 80
    return str(ipaddress.IPv6Address(prefix_l | random))


def _output_folder_type(value):
    folder = Path(value)
    if not folder.is_dir():
        raise ValueError(f'Path "{folder}" is not a folder')
    return folder


def _file_type(value):
    config = Path(value)
    if not config.exists() or not config.is_file():
        raise ValueError(
            'Configuration file must exist and must be a regular file.\n')
    return config


def _main():
    parser = argparse.ArgumentParser(
        description='Wireguard IPv6 Client Server Configurator')
    parser.add_argument(
        '-w', '--wireguard',
        dest='wireguard_path',
        type=_file_type,
        default=shutil.which('wg'),
        help='Path to Wireguard executable')

    subparsers = parser.add_subparsers(required=True)
    subparsers.dest = 'command'

    build = subparsers.add_parser('build', help='Build configuration files')
    build.add_argument(
        dest='outdir',
        type=_output_folder_type,
        help='Output folder')
    build.add_argument(
        dest='server_csv',
        type=_file_type,
        help='Path to server CSV configuration file')
    build.add_argument(
        dest='client_csv',
        type=_file_type,
        help='Path to client CSV configuration file')
    build.add_argument(
        '-q', '--qrencode',
        dest='qrencode_path',
        type=_file_type,
        default=shutil.which('qrencode'),
        help='Path to Qrencode executable')
    build.add_argument(
        '-d', '--dry-run',
        dest='dry_run',
        action='store_true',
        help='Run without writing files')

    subparsers.add_parser('server', help='Generate a new server CSV line')
    subparsers.add_parser('client', help='Generate a new client CSV line')

    args = parser.parse_args()

    if args.wireguard_path is None:
        print(
            'Cannot find the "wg" executable.'
            'Install it or provide a path with -w/--wireguard (placed before the command).')
        return

    if args.command == 'build':
        wgcs = WireguardClientServer(
            args.wireguard_path, args.qrencode_path, args.server_csv, args.client_csv)
        if not args.dry_run:
            wgcs.server_output(args.outdir)
            wgcs.client_output(args.outdir)

    elif args.command == 'server':
        print(
            f'wg-name,{gen_ula()}/48,<domain:443>,51820,{gen_privatekey(args.wireguard_path)}')

    elif args.command == 'client':
        print(f'client-name,fd::/64,25,{gen_privatekey(args.wireguard_path)},'
              f'{gen_presharedkey(args.wireguard_path)}')


if __name__ == '__main__':
    _main()
