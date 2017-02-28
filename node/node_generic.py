#!/usr/bin/env python

## Generic Utility Functions:
            
def raw_input_enter():
    print 'PRESS ENTER...'
    raw_input()


def ellipsis_cut(s,
                 n=60,
                 ):
    s=unicode(s)
    if len(s)>n+1:
        return s[:n].rstrip()+u"..."
    else:
        return s

    

def terminal_size():
    """
    Get terminal size.
    """
    h, w, hp, wp = struct.unpack('HHHH',fcntl.ioctl(0,
                                                    termios.TIOCGWINSZ,
                                                    struct.pack('HHHH', 0, 0, 0, 0),
                                                    ))
    return w, h

def space_pad(s,
              n=20,
              center=False,
              ch = '.'
              ):
    if center:
        return space_pad_center(s,n,ch)    
    s = unicode(s)
    #assert len(s) <= n,(n,s)
    return s + (ch * max(0,n-len(s)))

def usage(functions,
          glb,
          entry_point_name = False,
          ):
    """
    Print usage of all passed functions.
    """
    try:
        tw,th = terminal_size()
    except:
        tw,th = 80,40
                   
    print
    
    print 'USAGE:',(entry_point_name or ('python ' + sys.argv[0])) ,'<function_name>'
        
    print
    print 'Available Functions:'
    
    for f in functions:
        ff = glb[f]
        
        dd = (ff.__doc__ or '').strip() or 'NO_DOCSTRING'
        if '\n' in dd:
            dd = dd[:dd.index('\n')].strip()

        ee = space_pad(f,ch='.',n=40)
        print ee,
        print ellipsis_cut(dd, max(0,tw - len(ee) - 5))
    
    sys.exit(1)

    
def set_console_title(title):
    """
    Set console title.
    """
    try:
        title = title.replace("'",' ').replace('"',' ').replace('\\',' ')
        cmd = "printf '\033k%s\033\\'" % title
        system(cmd)
    except:
        pass

##
#### Time functions:
##

from datetime import datetime, timedelta
import dateutil.parser
from time import time
from time import mktime

def nth(n):
    """
    Formats an ordinal.
    Doesn't handle negative numbers.

    >>> nth(1)
    '1st'
    >>> nth(0)
    '0th'
    >>> [nth(x) for x in [2, 3, 4, 5, 10, 11, 12, 13, 14]]
    ['2nd', '3rd', '4th', '5th', '10th', '11th', '12th', '13th', '14th']
    >>> [nth(x) for x in [91, 92, 93, 94, 99, 100, 101, 102]]
    ['91st', '92nd', '93rd', '94th', '99th', '100th', '101st', '102nd']
    >>> [nth(x) for x in [111, 112, 113, 114, 115]]
    ['111th', '112th', '113th', '114th', '115th']
    """
    assert n >= 0
    if n % 100 in [11, 12, 13]:
        return '%sth' % n
    return {1: '%sst', 2: '%snd', 3: '%srd'}.get(n % 10, '%sth') % n


def timetuple(s):
    """htime(x) -> (days, hours, minutes, seconds)"""
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return (d, h, m, s)


def htime(s,
          show_seconds=True,
          min_digits = 2,
          max_digits = 2,
          ):
    """    """
    
    s = int(s)
    
    if s < 0:
        s = 0
    
    #d, s = divmod(s, 86400)
    #h, s = divmod(s, 3600)
    #m, s = divmod(s, 60)
    
    y =  s // 31536000 #365 days
    mm = s // 2592000 #30 days
    d =  s // 86400
    h =  s // 3600
    m =  s // 60

    #(d, h, m, s) = timetuple(s)
    
    x = []
    if y and ((len(str(y)) >= min_digits) or (len(str(mm)) > max_digits)):
        if y == 1:
            x.append('%s year' % y)
        else:
            x.append('%s years' % y)
    elif mm and ((len(str(mm)) >= min_digits) or (len(str(d)) > max_digits)):
        if mm == 1:
            x.append('%s months' % mm)
        else:
            x.append('%s months' % mm)
    elif d and ((len(str(d)) >= min_digits) or (len(str(h)) > max_digits)):
        if d == 1:
            x.append('%s day' % d)
        else:
            x.append('%s days' % d)
    elif h and ((len(str(h)) >= min_digits) or (len(str(m)) > max_digits)):
        if h == 1:
            x.append('%s hour' % h)
        else:
            x.append('%s hours' % h)
    elif m and ((len(str(m)) >= min_digits) or (len(str(s)) > max_digits)):
        if m == 1:
            x.append('%s minute' % m)
        else:
            x.append('%s minutes' % m)
    elif show_seconds:
        if s == 1:
            x.append('%s second' % s)
        else:
            x.append('%s seconds' % s)
    if not x:
        if show_seconds:
            x = ['%s seconds' % s]
        else:
            x = ['0 minutes']
    x.append(' ago')
    return ''.join(x)


def htime_ago(tt):
    return htime((time() - tt))


def datestr_to_epoch(ds):
    d2 = dateutil.parser.parse(ds)
    t = d2.astimezone(dateutil.tz.tzutc())
    t2 = mktime(t.timetuple())
    return t2
    

##
####
##

import sys
from os import system

def setup_main(functions,
               glb,
               entry_point_name = False,
               ):
    """
    Helper for invoking functions from command-line.
    """
        
    if len(sys.argv) < 2:
        usage(functions,
              glb,
              entry_point_name = entry_point_name,
              )
        return

    f=sys.argv[1]
    
    if f not in functions:
        print 'FUNCTION NOT FOUND:',f
        usage(functions,
              glb,
              entry_point_name = entry_point_name,
              )
        return

    title = (entry_point_name or sys.argv[0]) + ' '+ f
    
    set_console_title(title)
    
    print 'STARTING:',f + '()'

    ff=glb[f]

    ff(via_cli = True) ## New: make it easier for the functions to have dual CLI / API use.

