#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import subprocess

import gdb

import pwndbg.color.memory as M
import pwndbg.memory
import pwndbg.typeinfo
import pwndbg.vmmap


parser = argparse.ArgumentParser(description='Print abbreviated vmmap that includes unmapped areas')
parser.add_argument('address', default=None, nargs='?')

def short_page_str(page):
    width = 2 + 2*pwndbg.typeinfo.ptrsize
    fmt_string = "%#{}x %#{}x %s %#{}x  %s"
    fmt_string = fmt_string.format(width, width, width)
    return fmt_string % (
        page.vaddr,
        page.vaddr+page.memsz,
        page.permstr,
        page.memsz,
        page.objfile or ''
    )


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def minfo(address=None):
    pages = pwndbg.vmmap.get()
    prev_end = 0

    print(M.legend())
    for page in pages:
        if prev_end < page.vaddr:
            print(short_page_str(pwndbg.memory.Page(prev_end, page.vaddr - prev_end, 0, 0, '(empty)')))
        prev_end = page.vaddr + page.memsz
        print(M.get(page.vaddr, text=short_page_str(page)))
