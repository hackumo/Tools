# Released under the MIT License
#
# Copyright (c) Hackumo (https://github.com/hackumo)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import hashlib
import socket

import click
import pefile
import requests
from utils import clefia


def lookup_domain(domain: str, max_tries: int = 5) -> str:
    for i in range(max_tries):
        try:
            r = requests.get(f'https://networkcalc.com/api/dns/lookup/{domain}')
            data = r.json()
            if data['status'] != 'OK':
                continue
            return data['records']['A'][0]['address']
        except:
            pass
    return ''


def decrypt(filename: str, ip: str, data: bytearray) -> bytearray:
    ip = socket.inet_aton(ip)
    key = filename.upper().encode() + ip

    iv = hashlib.sha3_256(key).digest()[4:20]
    key = hashlib.sha3_256(key).digest()[:16]

    return clefia.decrypt_cbc(data, key, iv)


@click.group(name='windows')
def windows_tools():
    """Decrypt Windows-specific tools"""
    pass


@windows_tools.command(
    name='loader',
    help='Decrypt the configuration Decoy Dog loader for Windows'
)
@click.option(
    '--name',
    required=True,
    help='Filename of Decoy Dog loader')
@click.option(
    '--file',
    type=click.Path(
        exists=True,
        readable=True,
        dir_okay=False
    ),
    required=True,
    help='Path to Decoy Dog loader'
)
@click.option(
    '--ip',
    help='IP address of the domain without the character "-" from the Decoy Dog loader configuration'
)
def loader(name, file, ip):
    pe = pefile.PE(file)

    for section in pe.sections:
        dns_commands = []
        if section.Name.strip(b'\x00') == b'.rdata':
            data = section.get_data()
            key = 0
            offset = 0
            for k in range(20):
                decrypted = bytearray()
                if data[offset] == 0xff:
                    for j in range(256):
                        if data[offset + 1] == 0:
                            break
                        decrypted.append((data[offset + 1] ^ j ^ (key - 15 + 0x100)) & 0xff)
                        offset += 1
                    key += 1
                    dns_commands.append(decrypted)
                offset += 1

            offset = data.find(b'http\x00') + 4
            while data[offset] == 0:
                offset += 1

            if not ip:
                for command in dns_commands:
                    if command[0] != ord('-'):
                        ip = lookup_domain(command)
                        break
                if not ip:
                    click.echo(
                        f'[!] Can\'t lookup {command.decode()}. Try to find historical data through Passive DNS.')

            if ip:
                payload_path = decrypt(name, ip, data[offset:offset + 0x100])

            click.echo('[+] DNS commands:')
            for h in dns_commands:
                click.echo(f'  {h.decode()}')
            try:
                payload_path = payload_path.decode().rstrip('\x00')
                click.echo(f'[+] Payload path: {payload_path}')
            except:
                click.echo(f'[!] Can\'t decrypt payload path, try --ip option')

            break
    else:
        click.echo('[!] Can\'t find .rdata section')


@windows_tools.command(
    name='payload',
    help='Decrypt Decoy Dog payload for Windows'
)
@click.option(
    '--name',
    required=True,
    help='Filename of Decoy Dog loader'
)
@click.option(
    '--file',
    type=click.Path(
        exists=True,
        readable=True,
        dir_okay=False
    ),
    required=True,
    help='Path to Decoy Dog encrypted payload'
)
@click.option(
    '--ip',
    required=True,
    help='IP address of the domain without the character "-" from the Decoy Dog loader configuration'
)
def payload(name, file, ip):
    with open(file, 'rb') as f:
        encrypted = f.read()

    decrypted_payload = decrypt(name, ip, encrypted)
    output_path = file + '.dec'
    with open(output_path, mode='wb+') as f:
        f.write(decrypted_payload)
    click.echo(f'[+] Decrypted payload was written to {output_path}')
