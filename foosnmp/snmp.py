# Copyright (c) 2007 D-Level s.r.l. - All rights reserved

# Based on pynetsnmp-0.26.5 original code by Zenoss, Inc.

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

__all__ = [
    'SNMPManager',
    'SNMPSession',
    'SnmpError',
    'str_to_oid',
    'strs_to_oids',
    'oid_to_str',
    'oids_to_strs',
    'oid_to_dot',
    'oids_to_dots',
    'get_oid_info',
    'get_snmp_error',
    'mkoid',
    'create_string_buffer',
    'lib',
    'get_enum_dict',
    'setup_library',
    'add_mib_dir',
    'read_module',
    'init_mib',
]

# pylint: disable=unused-wildcard-import,invalid-name
#----------------------------------------------------------------------------

import os
import sys
import time
from select import select
import threading
import traceback

import struct
from ctypes import *
from ctypes.util import find_library

from .constants import *

#----------------------------------------------------------------------------

from .Singleton import Singleton

#----------------------------------------------------------------------------


def syncronized(method, mutex_finder=lambda x: x.mutex):
    def m(self, *args, **kargs):
        mutex = mutex_finder(self)

        mutex.acquire()
        try:
            return method(self, *args, **kargs)
        finally:
            mutex.release()

    m.real_method = method
    return m


#----------------------------------------------------------------------------
# load libraries

# freebsd stuff
if sys.platform.find('free') > -1:
    find_library_orig = find_library

    def find_library(name):
        for name in [
                '/usr/lib/lib%s.so' % name, '/usr/local/lib/lib%s.so' % name
        ]:
            if os.path.exists(name):
                return name
        return find_library_orig(name)


try:
    crypto = CDLL(find_library('crypto'), RTLD_GLOBAL)
except Exception:
    pass

lib_path = find_library('netsnmp')

lib = CDLL(lib_path)
lib.netsnmp_get_version.restype = c_char_p

#----------------------------------------------------------------------------
# type definitions

c_int_p = c_void_p
authenticator = CFUNCTYPE(c_char_p, c_int_p, c_char_p, c_int)
oid = c_long
u_long = c_ulong
u_short = c_ushort
u_char_p = c_char_p
u_int = c_uint
size_t = c_size_t
u_char = c_byte


class netsnmp_session(Structure):
    pass


class netsnmp_pdu(Structure):
    pass


# int (*netsnmp_callback) (int, netsnmp_session *, int, netsnmp_pdu *, void *);
netsnmp_callback = CFUNCTYPE(c_int, c_int,
                             POINTER(netsnmp_session), c_int,
                             POINTER(netsnmp_pdu), c_void_p)

version = lib.netsnmp_get_version()
float_version = float('.'.join(version.split('.')[:2]))
localname = []
param_name = []

if float_version < 5.7:
    raise ImportError("netsnmp version 5.7 or greater is required")

class netsnmp_container_s(Structure): pass

netsnmp_session._fields_ = [
    ('version', c_long),
    ('retries', c_int),
    ('timeout', c_long),
    ('flags', u_long),
    ('subsession', POINTER(netsnmp_session)),
    ('next', POINTER(netsnmp_session)),
    ('peername', c_char_p),
    ('remote_port', u_short),
    ('localname', c_char_p),
    ('local_port', u_short),
    ('authenticator', authenticator),
    ('callback', netsnmp_callback),
    ('callback_magic', c_void_p),
    ('s_errno', c_int),
    ('s_snmp_errno', c_int),
    ('sessid', c_long),
    ('community', u_char_p),
    ('community_len', size_t),
    ('rcvMsgMaxSize', size_t),
    ('sndMsgMaxSize', size_t),
    ('isAuthoritative', u_char),
    ('contextEngineID', u_char_p),
    ('contextEngineIDLen', size_t),
    ('engineBoots', u_int),
    ('engineTime', u_int),
    ('contextName', c_char_p),
    ('contextNameLen', size_t),
    ('securityEngineID', u_char_p),
    ('securityEngineIDLen', size_t),
    ('securityName', c_char_p),
    ('securityNameLen', size_t),
    ('securityAuthProto', POINTER(oid)),
    ('securityAuthProtoLen', size_t),
    ('securityAuthKey', u_char * USM_AUTH_KU_LEN),
    ('securityAuthKeyLen', c_size_t),
    ('securityAuthLocalKey', c_char_p),
    ('securityAuthLocalKeyLen', c_size_t),
    ('securityPrivProto', POINTER(oid)),
    ('securityPrivProtoLen', c_size_t),
    ('securityPrivKey', c_char * USM_PRIV_KU_LEN),
    ('securityPrivKeyLen', c_size_t),
    ('securityPrivLocalKey', c_char_p),
    ('securityPrivLocalKeyLen', c_size_t),
    ('securityModel', c_int),
    ('securityLevel', c_int),
    ('paramName', c_char_p),
    ('securityInfo', c_void_p),
    ('transport_configuration', POINTER(netsnmp_container_s)),
    ('myvoid', c_void_p),
]

dataFreeHook = CFUNCTYPE(c_void_p)


class counter64(Structure):
    _fields_ = [
        ('high', c_ulong),
        ('low', c_ulong),
    ]


class netsnmp_vardata(Union):
    _fields_ = [
        ('integer', POINTER(c_long)),
        ('uinteger', POINTER(c_ulong)),
        ('string', c_char_p),
        ('objid', POINTER(oid)),
        ('bitstring', POINTER(c_ubyte)),
        ('counter64', POINTER(counter64)),
        ('floatVal', POINTER(c_float)),
        ('doubleVal', POINTER(c_double)),
    ]


class netsnmp_variable_list(Structure):
    pass


netsnmp_variable_list._fields_ = [
    ('next_variable', POINTER(netsnmp_variable_list)),
    ('name', POINTER(oid)),
    ('name_length', c_size_t),
    ('type', c_char),
    ('val', netsnmp_vardata),
    ('val_len', c_size_t),
    ('name_loc', oid * MAX_OID_LEN),
    ('buf', c_char * 40),
    ('data', c_void_p),
    ('dataFreeHook', dataFreeHook),
    ('index', c_int),
]

netsnmp_pdu._fields_ = [
    ('version', c_long),
    ('command', c_int),
    ('reqid', c_long),
    ('msgid', c_long),
    ('transid', c_long),
    ('sessid', c_long),
    ('errstat', c_long),
    ('errindex', c_long),
    ('time', c_ulong),
    ('flags', c_ulong),
    ('securityModel', c_int),
    ('securityLevel', c_int),
    ('msgParseModel', c_int),
    ('transport_data', c_void_p),
    ('transport_data_length', c_int),
    ('tDomain', POINTER(oid)),
    ('tDomainLen', c_size_t),
    ('variables', POINTER(netsnmp_variable_list)),
    ('community', c_char_p),
    ('community_len', c_size_t),
    ('enterprise', POINTER(oid)),
    ('enterprise_length', c_size_t),
    ('trap_type', c_long),
    ('specific_type', c_long),
    ('agent_addr', c_char * 4),
    ('contextEngineID', c_char_p),
    ('contextEngineIDLen', c_size_t),
    ('contextName', c_char_p),
    ('contextNameLen', c_size_t),
    ('securityEngineID', c_char_p),
    ('securityEngineIDLen', c_size_t),
    ('securityName', c_char_p),
    ('securityNameLen', c_size_t),
    ('priority', c_int),
    ('range_subid', c_int),
    ('securityStateRef', c_void_p),
]

netsnmp_pdu_p = POINTER(netsnmp_pdu)


class netsnmp_tree(Structure):
    pass


class netsnmp_enum_list(Structure):
    pass

netsnmp_enum_list._fields_ = [
    ('next', POINTER (netsnmp_enum_list)),
    ('value', c_int),
    ('label', c_char_p)
]

class netsnmp_range_list(Structure):
    pass


class netsnmp_index_list(Structure):
    pass


netsnmp_tree._fields_ = [
    ('child_list', POINTER(netsnmp_tree)),
    ('next_peer', POINTER(netsnmp_tree)),
    ('next', POINTER(netsnmp_tree)),
    ('parent', POINTER(netsnmp_tree)),
    ('label', c_char_p),
    ('subid', c_ulong),
    ('modid', c_int),
    ('number_modules', c_int),
    ('module_list', c_int_p),
    ('tc_index', c_int),
    ('type', c_int),
    ('access', c_int),
    ('status', c_int),
    ('enums', POINTER(netsnmp_enum_list)),
    ('ranges', POINTER(netsnmp_range_list)),
    ('indexes', POINTER(netsnmp_index_list)),
    ('augments', c_char_p),
    ('varbinds', POINTER(netsnmp_variable_list)),
    ('hint', c_char_p),
    ('units', c_char_p),
    ('printomat', CFUNCTYPE(c_char_p, c_size_t, c_size_t, c_int,
                            POINTER(netsnmp_variable_list), c_void_p, c_char_p,
                            c_char_p)),
    ('printer', c_void_p),
    ('description', c_char_p),
    ('reference', c_char_p),
    ('reported', c_int),
    ('defaultValue', c_char_p),
]


class netsnmp_log_message(Structure):
    pass


netsnmp_log_message_p = POINTER(netsnmp_log_message)

log_callback = CFUNCTYPE(c_int, c_int, netsnmp_log_message_p, c_void_p)

netsnmp_log_message._fields_ = [
    ('priority', c_int),
    ('msg', c_char_p),
]


class netsnmp_transport(Structure):
    pass


netsnmp_transport._fields_ = [
    ('domain', POINTER(oid)),
    ('domain_length', c_int),
    ('local', c_char_p),
    ('local_length', c_int),
    ('remote', c_char_p),
    ('remote_length', c_int),
    ('sock', c_int),
    ('flags', c_uint),
    ('data', c_void_p),
    ('data_length', c_int),
    ('msgMaxSize', c_size_t),
    ('f_recv', c_void_p),
    ('f_send', c_void_p),
    ('f_close', c_void_p),
    ('f_accept', c_void_p),
    ('f_fmtaddr', c_void_p),
]
lib.netsnmp_tdomain_transport.restype = POINTER(netsnmp_transport)

# int snmp_input(int, netsnmp_session *, int, netsnmp_pdu *, void *);
snmp_input_t = CFUNCTYPE(c_int, c_int,
                         POINTER(netsnmp_session), c_int, netsnmp_pdu_p,
                         c_void_p)


class UnknownType(Exception):
    pass


class timeval(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long),
    ]


#----------------------------------------------------------------------------
# lib function defs
# 
# format is:
#	'func_name' : (
#		c_char_p, # restype
#		(c_int, c_int), # argtypes
#		None, #errcheck
#	),

LIB_FUNCTIONS = {
    # main
    'snmp_pdu_create': (netsnmp_pdu_p, (), None),
    'snmp_open': (POINTER(netsnmp_session), (), None),
    'snmp_sess_open': (POINTER(netsnmp_session), (), None),
    'snmp_api_errstring': (c_char_p, (c_int, ), None),
    'snmp_errstring': (c_char_p, (c_int, ), None),
    'snmp_error':
    (None, (POINTER(netsnmp_session), c_int_p, c_int_p, c_char_p), None),
    'snmp_sess_error':
    (None, (POINTER(netsnmp_session), c_int_p, c_int_p, c_char_p), None),
    # storage space
    'netsnmp_ds_set_boolean': (c_int, (c_int, c_int, c_int), None),
    'netsnmp_ds_get_boolean': (c_int, (c_int, c_int), None),
    'netsnmp_ds_toggle_boolean': (c_int, (c_int, c_int), None),
    'netsnmp_ds_set_int': (c_int, (c_int, c_int, c_int), None),
    'netsnmp_ds_get_int': (c_int, (c_int, c_int), None),
    'netsnmp_ds_set_string': (c_int, (c_int, c_int, c_char_p), None),
    'netsnmp_ds_get_string': (c_char_p, (c_int, c_int), None),
    'netsnmp_ds_set_void': (c_int, (c_int, c_int, c_void_p), None),
    'netsnmp_ds_get_void': (c_void_p, (c_int, c_int), None),
    # mib parsing
    'init_mib': (None, (), None),
    'shutdown_mib': (None, (), None),
    'netsnmp_set_mib_directory': (None, (c_char_p), None),
    'netsnmp_get_mib_directory': (c_char_p, (), None),
    'snprint_description':
    (c_int, (c_char_p, size_t, POINTER(oid), size_t, c_int), None),
    'snprint_value': (c_int, (c_char_p, size_t, POINTER(oid), size_t,
                              POINTER(netsnmp_variable_list)), None),
    'read_mib': (POINTER(netsnmp_tree), (c_char_p), None),
    'get_tree': (POINTER(netsnmp_tree), (), None),
    'get_tree_head': (POINTER(netsnmp_tree), (), None),
}
UNSUPPORTED_FUNCTIONS = []


def setup_lib_functions():
    for k, v in LIB_FUNCTIONS.iteritems():
        if v is None:
            continue
        try:
            f = getattr(lib, k)
            f.restype = v[0]
            if isinstance(v[1], tuple) and v[1]:
                f.argtypes = v[1]
            if v[2]:
                f.errcheck = v[2]
        except:
            UNSUPPORTED_FUNCTIONS.append(k)


setup_lib_functions()


def __shutdown_mib():
    pass


def __netsnmp_set_mib_directory(path):
    if path[0] in ('-', '+'):
        b = path[0] == '-'
        path = path[1:]
        curr_path = lib.netsnmp_ds_get_string(
            NETSNMP_DS_LIBRARY_ID,
            NETSNMP_DS_LIB_MIBDIRS, )
        if b:
            a = path
            b = curr_path
        else:
            a = curr_path
            b = path

        path = os.pathsep.join(filter(None, (a, b)))
    lib.netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIBDIRS,
                              path)


def __netsnmp_get_mib_directory():
    lib.netsnmp_ds_get_string(
        NETSNMP_DS_LIBRARY_ID,
        NETSNMP_DS_LIB_MIBDIRS, )


def __snprint_description(buff, l, oid, s, i):
    pass


FUNCTION_REPLACEMENTS = {
    'shutdown_mib': __shutdown_mib,
    'netsnmp_set_mib_directory': __netsnmp_set_mib_directory,
    'netsnmp_get_mib_directory': __netsnmp_get_mib_directory,
    'snprint_description': __snprint_description,
}
for k in UNSUPPORTED_FUNCTIONS:
    setattr(lib, k, FUNCTION_REPLACEMENTS.get(k, None))

#----------------------------------------------------------------------------
# decoding stuff


def to_oid(l):
    if l:
        r = (oid * len(l))()
        for i, v in enumerate(l):
            r[i] = v
    else:
        r = l
    return r


def str_to_oid(s):
    if isinstance(s, basestring):
        if s[:2] == '.1':
            #s = 'iso' + s[2:]
            r = map(int, filter(None, s.split('.')))
        else:
            an_oid = (oid * MAX_OID_LEN)()
            length = c_size_t(len(an_oid))
            r = lib.get_node(s, an_oid, byref(length))
            if r:
                r = an_oid[:length.value]
            else:
                r = None
    else:
        r = s
    return r


def strs_to_oids(oids):
    return [str_to_oid(oid) for oid in oids]


def oid_to_str(o):
    if o and not isinstance(o, basestring):
        cbuff = create_string_buffer('', SPRINT_MAX_LEN)
        length = c_size_t(len(cbuff))
        an_oid = (oid * len(o))()
        for i, v in enumerate(o):
            an_oid[i] = v
        r = lib.snprint_objid(cbuff, byref(length), an_oid, len(an_oid))
        if r:
            r = cbuff[:r]
        else:
            r = ''
    else:
        r = o
    return r


def oids_to_strs(oids):
    return [oid_to_str(o) for o in oids]


def oid_to_dot(o):
    return '.' + '.'.join(map(str, str_to_oid(o)))


def oids_to_dots(oids):
    return [oid_to_dot(o) for o in oids]


DEFAULT_OID_INFO_FIELDS = [
    'label',
    'type',
    'access',
    'status',
    'hint',
    'units',
    'description',
    'reference',
    'defaultValue',

    #'subid',
    #'modid',
    #'module_list',
    #'number_modules',
    #'tc_index',
    #'augments',
    #'reference',
    #'reported',
    #'varbinds',
]


def get_oid_info(o_str,
                 info=DEFAULT_OID_INFO_FIELDS,
                 convert_status=True,
                 convert_access=True,
                 convert_type=True):
    o = to_oid(str_to_oid(o_str))
    r = None
    if o:
        tp = lib.get_tree_head()

        tp = lib.get_tree(byref(o), c_size_t(len(o)), tp)

        if tp:
            r = {}
            for i in info:
                v = getattr(tp.contents, i)

                if convert_status and i is 'status':
                    v = status_type_to_str.get(v, v)
                elif convert_type and i is 'type':
                    asn_type = oid_type_to_asn_type.get(v, None)
                    r['type_id'] = v
                    r['type_name'] = asn_type_to_name.get(asn_type,
                                                          'octet_string')
                    r['type_py'] = asn_type_to_py.get(asn_type, repr(str))
                    v = asn_type_to_str.get(asn_type, v)
                elif convert_access and i is 'access':
                    v = access_type_to_str.get(v, v)

                r[i] = v
        else:
            r = None
    return r


def get_snmp_error(session=None):
    snmp_errno = None
    if session:
        if hasattr(session, 'contents'):
            if bool(session):
                snmp_errno = session.contents.s_snmp_errno
        else:
            snmp_errno = session.s_snmp_errno
        if session is not None:
            r = lib.snmp_api_errstring(snmp_errno)
    if snmp_errno is None:
        snmp_errno = c_int.in_dll(lib, 'snmp_errno').value
        r = lib.snmp_errstring(snmp_errno)
    return r


# NOT WORKING
#def dump_tree (o=None):
##('child_list', POINTER (netsnmp_tree)),
##('next_peer', POINTER (netsnmp_tree)),
##('next', POINTER (netsnmp_tree)),
##('parent', POINTER (netsnmp_tree)),
#tp = lib.get_tree_head ()
#if o is not None:
#o = to_oid (str_to_oid (o))
#tp = lib.get_tree (byref (o), c_size_t (len (o)), tp)

#data = {}

#def scan_node (node):
#n = node.contents
#c = 0
#while n:
#print '*n', n.label
#np = n
#while np:
#print '  +np', np.label
#child_list = np.child_list
#cl = child_list and child_list.contents
#if not cl:
#data[np.label] = asn_type_to_str.get (oid_type_to_asn_type.get (np.type, None), np.type)
#elif cl.child_list and cl.child_list.contents:
#print '    -cl', cl.label
##while cl and cl.child_list:
#scan_node (cl.child_list)
##cl = cl.child_list.contents.next_peer and cl.child_list.contents.next_peer.contents

#np = np.next_peer and np.next_peer.contents
#c+=1
#n = c<4 and n.next and n.next.contents

#if tp:
#scan_node (tp)
#return data

#-------------------------------------------------------------------------


def mkoid(n):
    if n:
        oids = (oid * len(n))()
        for i, v in enumerate(n):
            oids[i] = v
    else:
        oids = None
    return oids


def decode_oid(pdu):
    return tuple(
        [pdu.val.objid[i] for i in range(pdu.val_len / sizeof(u_long))])


def decode_ip(pdu):
    return '.'.join(map(str, pdu.val.bitstring[:4]))


def decode_big_int(pdu):
    int64 = pdu.val.counter64.contents
    return (int64.high << 32L) + int64.low


def decode_string(pdu):
    if pdu.val_len:
        return string_at(pdu.val.bitstring, pdu.val_len)
    return ''


access_type_to_str = {
    MIB_ACCESS_READONLY: 'ro',
    MIB_ACCESS_READWRITE: 'rw',
    MIB_ACCESS_WRITEONLY: 'wo',
    MIB_ACCESS_NOACCESS: 'na',
    MIB_ACCESS_NOTIFY: 'notify',
    MIB_ACCESS_CREATE: 'create',
}

status_type_to_str = {
    MIB_STATUS_MANDATORY: 'mandatory',
    MIB_STATUS_OPTIONAL: 'optional',
    MIB_STATUS_OBSOLETE: 'obsolete',
    MIB_STATUS_DEPRECATED: 'deprecated',
    MIB_STATUS_CURRENT: 'current',
}

oid_type_to_asn_type = {
    TYPE_OCTETSTR: chr(ASN_OCTET_STR),
    TYPE_INTEGER: chr(ASN_INTEGER),
    TYPE_NULL: chr(ASN_NULL),
    TYPE_OBJID: chr(ASN_OBJECT_ID),
    TYPE_BITSTRING: chr(ASN_BIT_STR),
    TYPE_IPADDR: chr(ASN_IPADDRESS),
    TYPE_COUNTER: chr(ASN_COUNTER),
    TYPE_GAUGE: chr(ASN_GAUGE),
    TYPE_TIMETICKS: chr(ASN_TIMETICKS),
    TYPE_COUNTER64: chr(ASN_COUNTER64),
    TYPE_OPAQUE: chr(ASN_OPAQUE),
}
asn_type_to_oid_type = dict([(s, i) for i, s in oid_type_to_asn_type.items()])

asn_type_to_name = {
    chr(ASN_OCTET_STR): 'octet_string',
    chr(ASN_BOOLEAN): 'boolean',
    chr(ASN_INTEGER): 'integer',
    chr(ASN_NULL): 'null',
    chr(ASN_OBJECT_ID): 'object_identifier',
    chr(ASN_BIT_STR): 'bits',
    chr(ASN_IPADDRESS): 'ipaddress',
    chr(ASN_COUNTER): 'counter',
    chr(ASN_GAUGE): 'gauge',
    chr(ASN_TIMETICKS): 'timeticks',
    chr(ASN_COUNTER64): 'counter64',
    chr(ASN_FLOAT): 'float',
    chr(ASN_DOUBLE): 'double',
    chr(ASN_OPAQUE): 'opaque',
}
name_to_asn_type = dict([(s, i) for i, s in asn_type_to_name.items()])

asn_type_to_py = {
    chr(ASN_OCTET_STR): repr(str),
    chr(ASN_BOOLEAN): repr(bool),
    chr(ASN_INTEGER): repr(int),
    chr(ASN_NULL): repr(str),
    chr(ASN_OBJECT_ID): repr(str),
    chr(ASN_BIT_STR): repr(str),
    chr(ASN_IPADDRESS): repr(str),
    chr(ASN_COUNTER): repr(int),
    chr(ASN_GAUGE): repr(int),
    chr(ASN_TIMETICKS): repr(int),
    chr(ASN_COUNTER64): repr(long),
    chr(ASN_FLOAT): repr(float),
    chr(ASN_DOUBLE): repr(float),
    chr(ASN_OPAQUE): repr(str),
}
py_to_asn_type = dict([(s, i) for i, s in asn_type_to_name.items()])

asn_type_to_str = {
    chr(ASN_OCTET_STR): 's',
    chr(ASN_BOOLEAN): 'i',
    chr(ASN_INTEGER): 'i',
    chr(ASN_NULL): 'n',
    chr(ASN_OBJECT_ID): 'o',
    chr(ASN_BIT_STR): 'b',
    chr(ASN_IPADDRESS): 'a',
    chr(ASN_COUNTER): '=',
    chr(ASN_GAUGE): '=',
    chr(ASN_TIMETICKS): 't',
    chr(ASN_COUNTER64): '=',
    chr(ASN_FLOAT): '=',
    chr(ASN_DOUBLE): '=',
    chr(ASN_OPAQUE): '=',
}
str_to_asn_type = dict([(s, i) for i, s in asn_type_to_str.items()])

decoder = {
    chr(ASN_OCTET_STR): decode_string,
    chr(ASN_BOOLEAN): lambda pdu: bool(pdu.val.integer.contents.value),
    chr(ASN_INTEGER): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_NULL): lambda pdu: None,
    chr(ASN_OBJECT_ID): decode_oid,
    chr(ASN_BIT_STR): decode_string,
    chr(ASN_IPADDRESS): decode_ip,
    chr(ASN_COUNTER): lambda pdu: pdu.val.uinteger.contents.value,
    chr(ASN_GAUGE): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_TIMETICKS): lambda pdu: pdu.val.uinteger.contents.value,
    chr(ASN_COUNTER64): decode_big_int,
    chr(ASN_APP_FLOAT): lambda pdu: pdu.val.float.contents.value,
    chr(ASN_APP_DOUBLE): lambda pdu: pdu.val.double.contents.value,
}

#DEFAULT_DECODERS = [
#chr (ASN_BOOLEAN),
#chr (ASN_INTEGER),
#chr (ASN_COUNTER),
#chr (ASN_GAUGE),
#chr (ASN_TIMETICKS),
#chr (ASN_COUNTER64),
#chr (ASN_APP_FLOAT),
#chr (ASN_APP_DOUBLE),
#]
#def default_decoder (var):
##for n in DEFAULT_DECODERS:
##print 'test', ord (n)
##try:
##return decoder[n] (pdu)
##except:
##pass
##return None
#oid = [var.name[i] for i in range (var.name_length)]
#print 'default_decoder', oid
#oid = mkoid (oid)
#buff = create_string_buffer ('', 1024)
#i = lib.snprint_value (buff, len (buff), oid, len (oid), var)
#print '  result', i
#return buff.value


def decode_type(var):
    oid = [var.name[i] for i in range(var.name_length)]
    decode = decoder.get(var.type, None)
    #print ' decoder', ord(var.type), decode, map (ord, decoder.keys ()), oid
    if not decode:
        # raise UnknownType(oid, ord(var.type))
        return (oid, None)
    return oid, decode(var)


def get_result(pdu):
    result = []
    var = pdu.variables

    while var:
        var = var.contents
        #print '======', decode_type (var)
        oid, val = decode_type(var)
        result.append((tuple(oid), val))
        var = var.next_variable

    return result

def get_enum_dict(info):
    result = {}
    enums = info["enums"]

    while enums:
        enum = enums.contents
        result[enum.value] = enum.label
        enums = enum.next

    return result

def setup_library(snmp_dir=None):
    local_dir = snmp_dir or os.path.abspath(os.path.dirname(__file__))
    mibs_path = os.path.join(local_dir, 'mibs')
    persistent_path = os.path.join(local_dir, 'persist')
    config_path = os.path.join(local_dir, 'etc')

    idx = os.path.join(mibs_path, '.index')
    if os.path.exists(idx):
        try:
            os.remove(idx)
        except:
            pass

    funcs = {
        'int': lib.netsnmp_ds_set_int,
        'bool': lib.netsnmp_ds_set_boolean,
        'str': lib.netsnmp_ds_set_string,
    }
    config = {
        NETSNMP_DS_LIB_MIBDIRS: ('str', mibs_path),
        NETSNMP_DS_LIB_PERSISTENT_DIR: ('str', persistent_path),
        NETSNMP_DS_LIB_CONFIGURATION_DIR: ('str', persistent_path),
        NETSNMP_DS_LIB_DONT_PERSIST_STATE: ('bool', 1),
        NETSNMP_DS_LIB_DEFAULT_PORT: ('int', 161),
    }
    for k, v in config.iteritems():
        t, d = v
        funcs[t](NETSNMP_DS_LIBRARY_ID, k, d)

def set_mib_dir(path):
    lib.netsnmp_set_mib_directory(path)

def add_mib_dir(path, append=True):
    if append:
        path = '+' + path
    else:
        path = '-' + path

    set_mib_dir(path)

def remove_mib_dir(path):
    curr_paths = get_mib_dir().split(os.path.pathsep)
    if path in curr_paths:
        curr_paths.remove(path)
    set_mib_dir(os.path.pathsep.join(curr_paths))

def get_mib_dir():
    return lib.netsnmp_get_mib_directory()

def read_mib(name):
    tp = lib.read_mib(name)
    return bool(tp and tp.contents)

def read_module(name):
    tp = lib.netsnmp_read_module(name)
    return tp != 0

def refresh_mibs():
    lib.shutdown_mib()
    lib.init_mib()

def init_mib():
    lib.init_mib()

#----------------------------------------------------------------------------
# exceptions


class SnmpError(Exception):
    def __init__(self, src, msg, log=False):
        self.src = src
        self.msg = msg
        txt = '%s: %s' % (src, msg)

        if log:
            lib.snmp_perror(src)

        Exception.__init__(self, txt)


class SnmpTimeout(SnmpError):
    pass


class SnmpPacketError(SnmpError):
    pass


#----------------------------------------------------------------------------
# session stuff


class SNMPManager(Singleton):
    SNMP_VERSIONS = {
        '1': SNMP_VERSION_1,
        '2': SNMP_VERSION_2c,
        '2c': SNMP_VERSION_2c,
        '3': SNMP_VERSION_3,
    }

    SNMP_SELECT_SEC = 1
    SNMP_SELECT_USEC = 0
    SNMP_SELECT_BLOCK = 1

    def init_class(self,
                   name='SNMPManager',
                   log=None,
                   max_fd=1024,
                   threaded_processor=True,
                   process_sessions_sleep=0.01,
                   local_dir=None):
        self.name = name
        self.local_dir = local_dir
        self.__log = log
        self.mutex = threading.RLock()

        self.sessions = {}
        self._signal_handlers = {}

        self._quit = False

        self._fdset2list = self._fdset2list_unix
        self._snmp_read = self._snmp_read_unix
        self.bits_per = struct.calcsize(c_long._type_) * 8

        self._max_fd = max_fd
        self._fdset = c_long * (max_fd / self.bits_per)

        self.setup_config()

        self.init_logger()

        self.log(LOG_DEBUG, 'Initializing Net-SNMP v%s library.' % version)

        lib.init_snmp(name)

        self.threaded_processor = threaded_processor
        self.process_sessions_sleep = process_sessions_sleep

        if threaded_processor:
            self._process_sessions_thread = threading.Thread(
                name='snmp_process_sessions', target=self.process_sessions)
            self._process_sessions_thread.setDaemon(True)
            self._process_sessions_thread.start()
        else:
            self._process_sessions_thread = None

        self.refresh_mibs()

    @syncronized
    def destroy(self, shutdown=True):
        if self.destroyed:
            return

        self._quit = True
        if self._process_sessions_thread and self._process_sessions_thread.isAlive(
        ):
            self._process_sessions_thread.join(5)
            if self._process_sessions_thread.isAlive():
                self._process_sessions_thread.kill()
            self._process_sessions_thread = None

        self.destroy_sessions()

        if shutdown:
            self.log(LOG_DEBUG, 'Shutting down Net-SNMP v%s library.' %
                     version)

            s = ' ' * 255
            cbuff = create_string_buffer(s, len(s))
            lib.snmp_shutdown(cbuff)

        self.destroy_logger()

        self._signal_handlers.clear()
        self.__log = None
        self.mutex = None

        self._snmp_read = None
        self._fdset = None
        self._fdset2list = None

        Singleton.destroy(self)

    # config ----------------------------------------------------------------

    def setup_config(self):
        setup_library(snmp_dir=self.local_dir)

    # signals ----------------------------------------------------------------

    def emit(self, slot, session, reqid, *args, **kargs):
        if slot in self._signal_handlers:
            handlers = []
            handlers.extend(self._signal_handlers[slot].get(session, {})
                            .values())
            handlers.extend(self._signal_handlers[slot].get(None, {}).values())
            for cb in (h['callback'] for h in handlers):
                try:
                    cb(self, slot, session, reqid, *args, **kargs)
                except Exception, e:
                    self.log(LOG_DEBUG, 'callback exception: %s' % str(e))
                    self.log(LOG_DEBUG,
                             traceback.format_exc(sys.exc_info()[2]))

    def bind(self, slot, uid, session, callback):
        self._signal_handlers.setdefault(slot, {}).setdefault(
            session, {})[uid] = {
                'callback': callback
            }

    def unbind(self, slot, uid, session=None):
        if slot in self._signal_handlers:
            for k, v in self._signal_handlers[slot].iteritems():
                if session is None or session == k:
                    if uid in v:
                        del v[uid]

    def process_sessions(self):
        while not self._quit:
            self.mutex.acquire()
            rd, t = self._snmp_select_info(self.SNMP_SELECT_SEC,
                                           self.SNMP_SELECT_USEC,
                                           self.SNMP_SELECT_BLOCK)
            if t is None:
                if not self.threaded_processor:
                    break

            if t is not None:
                rd, wd, xd = select(rd, [], [], t)
                if rd:
                    self._snmp_read(rd)
                else:
                    lib.snmp_timeout()

            self.timeout_async_requests()
            self.mutex.release()

            if self.process_sessions_sleep:
                time.sleep(self.process_sessions_sleep)

    def timeout_async_requests(self):
        now = time.time()

        for i in self.sessions.values():
            i.timeout_async_requests(now)

    def _snmp_select_info(self, sec=1, usec=0, block=0):
        timeout = timeval()
        timeout.tv_sec = sec
        timeout.tv_usec = usec

        f_block = c_int(0)

        rd = self._fdset()
        maxfd = c_int(0)  #self._max_fd)

        cnt = lib.snmp_select_info(
            byref(maxfd), byref(rd), byref(timeout), byref(f_block))
        rd = self._fdset2list(rd, maxfd.value, cnt)

        if block and f_block:
            t = None
        elif block and not f_block:
            t = timeout.tv_sec + float(timeout.tv_usec) / 1e6
        else:
            t = 0
        return rd, t

    def _fdset2list_unix(self, rd, n, cnt):
        result = []
        #for i in range (cnt):
        for i in range(len(rd)):
            if rd[i]:
                for j in range(0, self.bits_per):
                    bit = 0x00000001 << (j % self.bits_per)
                    if rd[i] & bit:
                        result.append(i * self.bits_per + j)
        return result

    def _snmp_read_unix(self, d):
        for fd in d:
            rd = self._fdset()
            rd[fd / self.bits_per] |= 1 << (fd % self.bits_per)
            lib.snmp_read(byref(rd))

    # mibs ----------------------------------------------------------------

    def set_mib_dir(self, path):
        lib.netsnmp_set_mib_directory(path)

    def add_mib_dir(self, path, append=True):
        add_mib_dir(path, append)

    def remove_mib_dir(self, path):
        remove_mib_dir(path)

    def get_mib_dir(self):
        return get_mib_dir()

    def read_mib(self, name):
        return read_mib(name)

    def read_module(self, name):
        return read_module(name)

    def refresh_mibs(self):
        return refresh_mibs()

    def init_mib(self):
        return init_mib()

    # logging ----------------------------------------------------------------

    PRIORITY_MAP = {
        LOG_EMERG: 'emergency',
        LOG_ALERT: 'alert',
        LOG_CRIT: 'critical',
        LOG_ERR: 'error',
        LOG_WARNING: 'warning',
        LOG_NOTICE: 'notice',
        LOG_INFO: 'info',
        LOG_DEBUG: 'debug',
    }

    def log(self, priority, msg):
        priority = self.PRIORITY_MAP.get(priority, priority)
        if self.__log:
            self.__log(priority, msg)
        else:
            print priority, ':', msg

    def _netsnmp_logger(self, a, b, msg):
        msg = cast(msg, netsnmp_log_message_p)
        priority = self.PRIORITY_MAP.get(msg.contents.priority, 'warning')
        if self.__log:
            self.__log(priority, msg.contents.msg.strip())
        else:
            print priority, ':', msg.contents.msg.strip()
        return 0

    def init_logger(self):
        self._netsnmp_logger_callback = log_callback(self._netsnmp_logger)

        lib.snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                                   SNMP_CALLBACK_LOGGING,
                                   self._netsnmp_logger_callback, 0)

        self._log_handler = lib.netsnmp_register_loghandler(
            NETSNMP_LOGHANDLER_CALLBACK, LOG_DEBUG)

    def destroy_logger(self):
        # commented becouse errors are generated on win32
        #lib.netsnmp_remove_loghandler (self._log_handler)
        self._netsnmp_logger_callback = None
        self._log_handler = None

    # sessions ----------------------------------------------------------------

    def add_session(self, name, version='1', **kargs):
        if not version in self.SNMP_VERSIONS:
            raise RuntimeError('Unknown SNMP version "%s"' % version)

        if 'community' in kargs and 'community_len' not in kargs:
            kargs['community_len'] = len(kargs['community'])
        if 'timeout' in kargs:
            if kargs['timeout'] is None:
                kargs['timeout'] = SNMP_DEFAULT_TIMEOUT
            else:
                kargs['timeout'] = int(kargs['timeout'] * 1e6)
        if 'retries' in kargs:
            if kargs['retries'] is None:
                kargs['retries'] = SNMP_DEFAULT_RETRIES

        s = SNMPSession(
            manager=self,
            name=name,
            version=self.SNMP_VERSIONS[version],
            **kargs)

        try:
            s.open()
            self.sessions[name] = s
        except SnmpError:
            s.destroy()
            s = None
            raise
        return s

    def add_trapd_session(self, name, peername, fileno=-1):
        s = SNMPSession(manager=self, name=name)
        try:
            s.trapd(peername, fileno)
            self.sessions[name] = s
        except SnmpError:
            s.destroy()
            s = None
            raise
        return s

    def remove_session(self, name):
        if name in self.sessions:
            s = self.sessions[name]
            del self.sessions[name]
            s.destroy()

    def reopen_sessions(self):
        for i in self.sessions.values():
            i.close()
            i.open()
        self.sessions.clear()

    def destroy_sessions(self):
        for i in self.sessions.values():
            i.destroy()
        self.sessions.clear()

    def find_session(self, sessid):
        r = None
        for v in self.sessions.values():
            if sessid == v.sess.contents.sessid:
                r = v
                break
        return r

    def __getitem__(self, name):
        return self.sessions[name]


class SNMPSession(object):
    ASYNC_REQUEST_TIMEOUT = 60

    def __init__(self, manager, name, results_as_list=False, **kargs):
        self.manager = manager
        self.name = name
        self.results_as_list = results_as_list
        self.kw = kargs
        self.mutex = threading.RLock()
        self.async_requests = {}
        self.async_wait_list = {}
        self.async_request_timeout = self.ASYNC_REQUEST_TIMEOUT

    def destroy(self):
        self.manager.mutex.acquire()
        self.close()
        self.manager.mutex.release()
        self.manager = None
        self.name = None
        self.kw = None
        self.sess = None
        self.mutex = None
        self._netsnmp_callback = None

    # requests --------------------------------------------------------------

    def open(self):
        sess = netsnmp_session()
        lib.snmp_sess_init(byref(sess))

        for attr, value in self.kw.items():
            setattr(sess, attr, value)

        sess.callback = self._netsnmp_callback  #self._get_callback ()
        sess.callback_magic = id(self)
        #lib.snmp_set_do_debugging (1)
        self.sess = lib.snmp_open(byref(sess))
        #lib.snmp_set_do_debugging (0)

        if not self.sess:
            raise SnmpError('snmp_open', get_snmp_error(sess))

    def close(self):
        if self.sess:
            lib.snmp_close(self.sess)
            self.sess = None

        self.async_requests.clear()

        for i in self.async_wait_list.values():
            if isinstance(i, threading._Event):
                i.set()
        self.async_wait_list.clear()

    # traps --------------------------------------------------------------

    def trapd(self, peername, fileno=-1):
        lib.netsnmp_udp_ctor()

        transport = lib.netsnmp_tdomain_transport(peername, 1, 'udp')
        if not transport:
            raise SnmpError('Unable to create transport', peername)

        if fileno >= 0:
            os.dup2(fileno, transport.contents.sock)

        sess = netsnmp_session()
        self.sess = lib.snmp_sess_init(byref(sess))
        if not self.sess:
            raise SnmpError(name, 'snmp_sess_init')

        sess.peername = SNMP_DEFAULT_PEERNAME
        sess.version = SNMP_DEFAULT_VERSION
        sess.community_len = SNMP_DEFAULT_COMMUNITY_LEN
        sess.retries = SNMP_DEFAULT_RETRIES
        sess.timeout = SNMP_DEFAULT_TIMEOUT
        sess.callback = self._netsnmp_callback
        sess.callback_magic = id(self)
        # sess.authenticator = None
        sess.isAuthoritative = SNMP_SESS_UNKNOWNAUTH
        rc = lib.snmp_add(self.sess, transport, None, None)
        if not rc:
            raise SnmpError(name, 'snmp_add')

    # utils ------------------------------------------------------

    def _create_request(self, packet_type):
        return lib.snmp_pdu_create(packet_type)

    def pdu_parse(self, pdu, buffer):
        cbuff = create_string_buffer(buffer, len(buffer))
        length = c_size_t(len(buffer))
        after_header = c_char_p()
        err = lib.snmpv3_parse(
            byref(pdu), cbuff, byref(length), byref(after_header), self.sess)
        if err:
            raise SnmpError('pdu_parse', lib.snmp_errstring(err))

    # info ------------------------------------------------------

    def get_description(self, oid, width=80, buffer_size=10240):
        oid = str_to_oid(oid)
        if oid is not None:
            oid = mkoid(oid)
            buff = create_string_buffer('', buffer_size)
            lib.snprint_description(buff, len(buff), oid, len(oid), width)
            r = buff.value
        else:
            r = ''
        return r

    # sync operations ------------------------------------------------------

    #def _handle_sync_request (self, name, req, exc_on_error):
    #response = netsnmp_pdu_p ()
    #status = lib.snmp_synch_response (self.sess, req, byref (response))
    #result = None
    #r = bool (response) and response.contents
    #try:
    #if status == STAT_SUCCESS:
    #if r and r.errstat == SNMP_ERR_NOERROR:
    #result = dict (get_result (r))
    #else:
    #if exc_on_error:
    #raise SnmpPacketError (name)
    #elif r:
    #result = lib.snmp_errstring (r.errstat)
    #elif status == STAT_TIMEOUT:
    #result = 'timeout'
    #if exc_on_error:
    #raise SnmpTimeout (name, result)
    #else: # STAT_ERROR
    #if r:
    #result = lib.snmp_errstring (r.errstat)
    #else:
    #result = get_snmp_error (self.sess) or 'Unknown Error'
    #if exc_on_error:
    #raise SnmpError (name, result)
    #finally:
    #if response:
    #lib.snmp_free_pdu (response)

    #return result

    def sync_get(self, oids, exc_on_error=False):
        return self.wait_async_request(
            self.async_get(oids, True, exc_on_error))

        #oids = strs_to_oids (oids)
        #req = self._create_request (SNMP_MSG_GET)

        #for oid in oids:

    #if oid is not None:
    #oid = mkoid (oid)
    #lib.snmp_add_null_var (req, oid, len (oid))
    #return self._handle_sync_request ('sync_get', req, exc_on_error)

    def sync_getbulk(self,
                     nonrepeaters,
                     maxrepetitions,
                     oids,
                     exc_on_error=False):
        return self.wait_async_request(
            self.async_getbulk(nonrepeaters, maxrepetitions, oids, True,
                               exc_on_error))

        #oids = strs_to_oids (oids)
        #req = self._create_request (SNMP_MSG_GETBULK)
        #req.contents.errstat = nonrepeaters
        #req.contents.errindex = maxrepetitions
        #for oid in oids:
    #if oid is not None:
    #oid = mkoid (oid)
    #lib.snmp_add_null_var (req, oid, len (oid))

    #return self._handle_sync_request ('sync_getbulk', req, exc_on_error)

    def sync_walk(self, root, exc_on_error=False):
        return self.wait_async_request(
            self.async_walk(root, True, exc_on_error))

        #req = self._create_request (SNMP_MSG_GETNEXT)
        #oid = mkoid (str_to_oid (root))
        #if oid is not None:

    #lib.snmp_add_null_var (req, oid, len (oid))

    #return self._handle_sync_request ('sync_getnext', req, exc_on_error)

    # async operations ------------------------------------------------------

    # had to implement the hack below becouse the _get_callback () method doesn't
    # work under OS X (why?)

    def _netsnmp_callback(operation, sp, reqid, pdu, magic):
        s = SNMPManager().find_session(sp.contents.sessid)
        if s:
            r = s.dispatch_callback(operation, sp, reqid, pdu, magic)
        else:
            r = 1
        return r
    _netsnmp_callback = netsnmp_callback(_netsnmp_callback)

    @syncronized
    def dispatch_callback(self, operation, sp, reqid, pdu, magic):
        try:
            if operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
                self.callback(pdu)
            elif operation == NETSNMP_CALLBACK_OP_TIMED_OUT:
                self.timeout(reqid)
            else:
                self._process_waiting_async_request(
                    reqid, "Unknown operation (%d)" % operation)
                self.manager.log(LOG_ERR, "Unknown operation (%d)" % operation)
        except Exception, ex:
            self._process_waiting_async_request(
                reqid, "Exception in dispatch_callback (%s)" % ex)
            self.manager.log(LOG_ERR, "Exception in dispatch_callback (%s)" %
                             ex)

        return 1

    #def _get_callback (self):
    #def _callback (operation, sp, reqid, pdu, magic):
    #try:
    #if operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
    #self.callback (pdu)
    #elif operation == NETSNMP_CALLBACK_OP_TIMED_OUT:
    #self.timeout (reqid)
    #else:
    #self._process_waiting_async_request (reqid, "Unknown operation (%d)" % operation)
    #self.manager.log (LOG_ERR, "Unknown operation (%d)" % operation)
    #except Exception, ex:
    ##self._process_waiting_async_request (reqid, "Exception in _callback (%s)" % ex)
    #self.manager.log (LOG_ERR, "Exception in _callback (%s)" % ex, ex)

    #return 1
    #_callback = netsnmp_callback (_callback)
    #return _callback

    COMMAND_TO_SLOT = {
        SNMP_MSG_GET: 'get',
        SNMP_MSG_GETNEXT: 'getnext',
        SNMP_MSG_GETBULK: 'getbulk',
        SNMP_MSG_SET: 'set',
        SNMP_MSG_INFORM: 'inform',
        SNMP_MSG_TRAP: 'trap',
        SNMP_MSG_TRAP2: 'trap2',
        SNMP_MSG_REPORT: 'report',
        SNMP_MSG_RESPONSE: 'response',
    }
    SLOT_TO_COMMAND = dict([(v, k) for k, v in COMMAND_TO_SLOT.iteritems()])

    def callback(self, pdu):
        reqid = pdu.contents.reqid
        if self.results_as_list:
            result = get_result(pdu.contents)
        else:
            result = dict(get_result(pdu.contents))

        if reqid in self.async_requests:
            rtype, timeout = self.async_requests.pop(reqid, (None, None))
            slot = self.COMMAND_TO_SLOT.get(rtype, None)
            b = self._process_waiting_async_request(reqid, result)
        else:
            slot = self.COMMAND_TO_SLOT.get(pdu.contents.command, 'result')
            b = False

        if b:
            if slot:
                self.manager.emit(slot, self.name, reqid, result)
                self.manager.emit('response', self.name, reqid, result)

    def timeout(self, reqid):
        if self._process_waiting_async_request(reqid, 'timeout'):
            self.manager.emit('timeout', self.name, reqid)

    @syncronized
    def _async_send_request(self, name, req, wait, exc_on_error):
        if not lib.snmp_send(self.sess, req):
            lib.snmp_free_pdu(req)
            result = get_snmp_error(self.sess)
            if exc_on_error:
                raise SnmpError(name, err)
        else:
            timeout = time.time() + self.async_request_timeout
            reqid = req.contents.reqid
            self.async_requests[reqid] = (name, timeout)
            if wait:
                e = threading.Event()
                e.timeout = timeout
                self.async_wait_list[reqid] = e
                result = (reqid, e)
            else:
                result = reqid
        return result

    def _process_waiting_async_request(self, reqid, result):
        b = True
        if reqid in self.async_wait_list:
            if isinstance(self.async_wait_list[reqid], threading._Event):
                e = self.async_wait_list[reqid]
                self.async_wait_list[reqid] = result
                e.set()
                b = False
        return b

    @syncronized
    def timeout_async_requests(self, now):
        for reqid in self.async_wait_list.keys():
            if isinstance(self.async_wait_list[reqid], threading._Event):
                e = self.async_wait_list[reqid]
                if e.timeout < now:
                    self.async_wait_list[reqid] = 'timeout'
                    e.set()

        for reqid in self.async_requests.keys():
            if self.async_requests[reqid][1] < now:
                del self.async_requests[reqid]

    def wait_async_request(self, result):
        reqid, e = result
        e.wait()
        self.mutex.acquire()
        try:
            result = self.async_wait_list.pop(reqid, None)
        finally:
            self.mutex.release()
        return result

    def async_get(self, oids, wait=False, exc_on_error=False):
        oids = strs_to_oids(oids)
        req = self._create_request(SNMP_MSG_GET)
        for oid in oids:
            if oid is not None:
                oid = mkoid(oid)
                lib.snmp_add_null_var(req, oid, len(oid))

        return self._async_send_request(SNMP_MSG_GET, req, wait, exc_on_error)

    def async_getbulk(self,
                      nonrepeaters,
                      maxrepetitions,
                      oids,
                      wait=False,
                      exc_on_error=False):
        req = self._create_request(SNMP_MSG_GETBULK)
        req.contents.errstat = nonrepeaters
        req.contents.errindex = maxrepetitions

        oids = strs_to_oids(oids)
        for oid in oids:
            if oid is not None:
                oid = mkoid(oid)
                lib.snmp_add_null_var(req, oid, len(oid))

        return self._async_send_request(SNMP_MSG_GETBULK, req, wait,
                                        exc_on_error)

    def async_walk(self, root, wait=False, exc_on_error=False):
        req = self._create_request(SNMP_MSG_GETNEXT)
        oid = mkoid(str_to_oid(root))
        if oid is not None:
            lib.snmp_add_null_var(req, oid, len(oid))

        return self._async_send_request(SNMP_MSG_GETNEXT, req, wait,
                                        exc_on_error)

    # set operations ------------------------------------------------------

    def _set(self, oids_values):
        req = self._create_request(SNMP_MSG_SET)

        for oid, value in oids_values:
            oid = str_to_oid(oid)
            if oid is not None:
                oid_type = get_oid_info(oid, ['type']).get('type', '=')
                if not oid_type:
                    oid_type = '='
                oid = mkoid(oid)
                lib.snmp_add_var(req, oid, len(oid), ord(oid_type), value)
        return req

    def sync_set(self, oids_values, exc_on_error=False):
        return self.wait_async_request(
            self.async_set(oids_values, True, exc_on_error))

        #req = self._set (oids_values, exc_on_error)
        #return self._handle_sync_request ('sync_set', req, exc_on_error)

    def async_set(self, oids_values, wait=False, exc_on_error=False):
        req = self._set(oids_values)
        return self._async_send_request(SNMP_MSG_SET, req, wait, exc_on_error)


if __name__ == '__main__':
    # Some stupid tests
    for t in range(1):
        print 'init manager'
        m = SNMPManager()

        print 'setup mib dirs'
        #m.add_mib_dir (os.path.abspath (os.path.join (os.path.basename (__file__), 'mibs')))
        #m.refresh_mibs ()
        print 'read_mib', m.read_mib(
            os.path.join('test', 'data', 'LINKSYS.MIB'))
        print 'mib dirs:', m.get_mib_dir()

        PEERNAME = 'localhost'
        SNMP_VERSION = '2'
        PUBLIC = 'public'
        PRIVATE = 'private'

        print 'add session'
        try:
            s = m.add_session(
                name='get_session',
                version=SNMP_VERSION,
                peername=PEERNAME,
                community=PUBLIC)
            set_s = m.add_session(
                name='set_session',
                version=SNMP_VERSION,
                peername=PEERNAME,
                community=PRIVATE)
        except SnmpError, exc:
            print 'ABORT on open session', exc
            m.destroy()
            sys.exit()

        mibs = [
            'sysDescr.0',
            'sysObjectID.0',
            'sysLocation.0',
            '.1.3.6.1.2.1.1.1.0',
            'sysUpTimeInstance',
            'ifOutOctets.1',
            'laLoadFloat.0',
            'snmpInTotalReqVars.0',
            'hrSystemProcesses.0',
        ]

        print 'get descriptions'
        for i in mibs:
            print i, '=' * 40
            print(i, str_to_oid(i), oid_to_str(str_to_oid(i)), get_oid_info(i)
                  )  #['type'])
            print s.get_description(i)

        print '- sync get'
        for i in range(1):
            r = s.sync_get(mibs)
            print '-' * 40
            if isinstance(r, dict):
                for k, v in r.iteritems():
                    try:
                        print '%s (%s) = %s' % (oid_to_str(k), k, v)
                    except:
                        #Failure ().print_brief_traceback ()
                        pass
            else:
                print 'ERROR:', r
        #m.destroy ()
        #sys.exit ()

        print '- sync getbulk'
        for i in range(1):
            r = s.sync_getbulk(0, 10, mibs)
            print '-' * 40
            if isinstance(r, dict):
                for k, v in r.iteritems():
                    try:
                        print '%s (%s) = %s' % (oid_to_str(k), k, v)
                    except:
                        #Failure ().print_brief_traceback ()
                        pass
            else:
                print 'ERROR:', r

        print '- sync walk'
        o = 'SNMPv2-MIB'
        for i in range(3):
            r = s.sync_walk(o)
            print '-' * 40
            if isinstance(r, dict):
                for k, v in r.iteritems():
                    o = k
                    try:
                        print '%s (%s) = %s' % (oid_to_str(k), k, v)
                    except:
                        #Failure ().print_brief_traceback ()
                        pass
            else:
                print 'ERROR:', r

        # ASYNC STUFF

        def timeout_cb(manager, slot, session, reqid):
            print '!', 'async timeout "%s"' % slot, (manager, session, reqid)

        def result_cb(manager, slot, session, reqid, r):
            print '=' * 40, 'async "%s"' % slot, (manager, session, reqid)
            if r:
                for k, v in r.iteritems():
                    o = k
                    try:
                        print '%s (%s) = %s' % (oid_to_str(k), k, v)
                    except:
                        #Failure ().print_brief_traceback ()
                        pass

        m.bind('response', '1', None, result_cb)
        m.bind('timeout', '1', None, timeout_cb)

        print '- async get',
        for i in range(1):
            r = s.async_get(mibs)
            print r
        print '* wait 5s'
        time.sleep(5)
        print '- async getbulk',
        for i in range(1):
            r = s.async_getbulk(0, 10, mibs)
            print r
        print '* wait 5s'
        time.sleep(5)
        print '- async walk',
        o = 'SNMPv2-MIB'
        r = s.async_walk(o)
        print r

        print '* wait 5s'
        time.sleep(5)
        print '- sync_set', set_s.sync_get(['sysLocation.0'])
        print '+ set result = ', set_s.sync_set([('sysLocation.0', 'Plaino')])
        print '- Udine = ', set_s.sync_get(['sysLocation.0'])
        print '* wait 5s'
        time.sleep(5)
        print '- async_set', set_s.async_get(['sysLocation.0'])
        print '+ set result = ', set_s.async_set([('sysLocation.0', 'Udine')])
        time.sleep(5)
        print '- Udine = ', set_s.async_get(['sysLocation.0'])
        print '* wait 5s'
        time.sleep(5)

        print 'destroy manager'
        m.unbind('response', '1')
        m.destroy()
