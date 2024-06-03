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
import struct

import click
from utils import clefia, nrv2e


def decrypt_block(data: bytearray, offset: int, key: bytes) -> (bytearray, int, int):
    uncompressed_size, compressed_size, flags = struct.unpack('<3L', data[offset:offset + 12])
    nonce = data[offset + 12:offset + 28]
    decrypted_block = clefia.decrypt_ctr(data[offset + 28:offset + 28 + compressed_size], key, nonce)
    if flags & 0b1000:
        decrypted_block = nrv2e.decompress(decrypted_block)
    return decrypted_block, uncompressed_size, compressed_size


@click.group(name='linux')
def linux_tools():
    """Decrypt Linux-specific tools"""
    pass


@linux_tools.command(
    name='loader',
    help='Decrypt the configuration of Decoy Dog loader for Linux'
)
@click.option(
    '--machine-id',
    required=True,
    type=click.File(
        'rb'
    ),
    help="""Path to the machine ID. It can be found in one of the following paths:

        \b
        /etc/machine-id
        /run/machine-id
        /var/lib/dbus/machine-id
        /var/db/dbus/machine-id
        /usr/local/etc/machine-id
        /sys/class/dmi/id/product_uuid
        /sys/class/dmi/id/board_serial
        /etc/hostid
        /proc/self/cgroup
        """
)
@click.option(
    '--file',
    required=True,
    type=click.File('rb'),
    help='Path to Decoy Dog loader'
)
def loader(machine_id, file):
    key = hashlib.md5(machine_id.read()).digest()

    decrypted_config, _, _ = decrypt_block(file.read(), 0x100, key)

    if decrypted_config[:4] == b'\xEE\x11\xFF\x00':
        payload_size = struct.unpack('I', decrypted_config[8:12])[0]
        payload_path = decrypted_config[12:].decode().strip('\x00')
        click.echo(f'[+] Payload path: {payload_path}')
        click.echo(f'[+] Payload size: {payload_size}')
    else:
        click.echo(f'[!] Can\'t decrypt config: invalid machine ID')


@linux_tools.command(
    name='payload',
    help='Decrypt Decoy Dog payload for Linux'
)
@click.option(
    '--machine-id',
    required=True,
    type=click.File(
        'rb'
    ),
    help="""Path to machine ID. It can be found in one of the following paths:

        \b
        /etc/machine-id
        /run/machine-id
        /var/lib/dbus/machine-id
        /var/db/dbus/machine-id
        /usr/local/etc/machine-id
        /sys/class/dmi/id/product_uuid
        /sys/class/dmi/id/board_serial
        /etc/hostid
        /proc/self/cgroup
        """
)
@click.option(
    '--file',
    required=True,
    type=click.File('rb'),
    help='Path to Decoy Dog encrypted payload'
)
def payload(machine_id, file):
    encrypted_payload = file.read()

    key = hashlib.md5(machine_id.read()).digest()

    offset = 0
    file_size = file.tell()
    block_num = 1
    decrypted_payload = bytearray()
    while offset < file_size - 16:
        decrypted_block, uncompressed_size, compressed_size = decrypt_block(encrypted_payload, offset, key)
        decrypted_payload += decrypted_block
        if block_num == 2 and len(decrypted_block) % 16:
            decrypted_payload += b'\x00' * (16 - (len(decrypted_block) % 16))
        offset += 28 + compressed_size
        block_num += 1

    if decrypted_payload[:4] != b'\x7fELF':
        click.echo('[!] Can\'t decrypt payload: invalid machine ID')
        return

    with open(file.name + '.dec', mode='wb+') as f:
        f.write(decrypted_payload)
    click.echo(f'[+] Decrypted payload was written to {file.name + ".dec"}')
