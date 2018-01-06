#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command to print the virtual memory map a la /proc/self/maps.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb
import six

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.compat
import pwndbg.vmmap


def pages_filter(s):
    gdbval_or_str = pwndbg.commands.sloppy_gdb_parse(s)

    # returns a module filter
    if isinstance(gdbval_or_str, six.string_types):
        module_name = gdbval_or_str
        return lambda page: module_name in page.objfile

    # returns an address filter
    elif isinstance(gdbval_or_str, six.integer_types + (gdb.Value,)):
        addr = gdbval_or_str
        return lambda page: addr in page

    else:
        raise argparse.ArgumentTypeError('Unknown vmmap argument type.')


parser = argparse.ArgumentParser()
parser.description = 'Print virtual memory map pages. Results can be filtered by providing address/module name.'
parser.add_argument('pages_filter', type=pages_filter, nargs='?', default=None,
                    help='Address or module name.')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def vmmap(pages_filter=None):
    pages = list(filter(pages_filter, pwndbg.vmmap.get()))

    if not pages:
        print('There are no mappings for specified address or module.')
        return

    print(M.legend())
    for page in pages:
        print(M.get(page.vaddr, text=str(page)))


addr_parser = argparse.ArgumentParser()
addr_parser.description = 'Print info about a specific virtual address.'
addr_parser.add_argument('addr', type=int, help='Address to examine.')


@pwndbg.commands.ArgparsedCommand(addr_parser)
@pwndbg.commands.OnlyWhenRunning
def xinfo(addr):
    pages = list(filter(lambda page: addr in page, pwndbg.vmmap.get()))

    if len(pages) == 0:
        print('There are no mappings for specified address {:#x}.'.format(addr))
        return

    page = pages[0]
    print(M.legend())
    print(M.get(page.vaddr, text=str(page)))
    print(' Offset: {:#x}'.format(int(addr - page.start)))

    