from pwndbg.memory import u64 as uint64
from pwndbg.vmmap import find
import argparse

parser = argparse.ArgumentParser(description='Shows offsets of the specified address to useful other locations')
parser.add_argument('address', default='$pc', help='Address to inspect')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def funcptrs(address):
    addr = int(address)
    page = find(addr)
    if page is None:
        print('Page {:#x} is not mapped'.format(page))
    
    print('Searching from {:#x} to {:#x} ({})'.format(
        page.start, page.end, page.objfile
    ))
    i = 0
    for target in range(page.start, page.end, 8):
        val = uint64(target)
        if find(val) is not None and find(val).execute:
            gdb.execute('telescope {} 1'.format(target))
