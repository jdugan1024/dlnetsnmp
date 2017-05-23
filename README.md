# foosnmp: a Python ctypes-based Net-SNMP wrapper module.

NOTE: This was originally written by Alessandro Iob. I have tried to contact
him but was unable to. This is my fork of the last code that was posted on the 
dlevel.com website. This is minimally maintained to support a legacy system and 
I would not recommend it as a starting point for a new project.

This is a small but almost complete wrapper for the [NetSNMP](http://net-snmp.sf.net/).
This library was originally based on the "pynetsnmp" module developed by cool people at 
[Zenoss](http://www.zenoss.com/).

The current version has been tested with Python 2.7 and NetSNMP 5.7.3.

## Features

- Synchronous and asynchronous "get", "getbulk", "walk" and "set" operations.
- MIB management: set/get MIB paths, load new MIBs, get OID descriptions
  from MIBs, oid to name (and vice versa) translation tools.
- Session management, internal asynchronous events management, pluggable logger
  and meaningful error reporting.
- Multi-platform: runs under Linux (and I think other Unixes also), Windows and OS X.

## Bugs and unsupported features

- Does not work if used from multiple-threads.
- Traps collection implemented but not tested.
- Tables not implemented.

You can find some simple tests and usage patters at the end of the "foosnmp.py" file.

# Installation

    pip install foosnmp
    
# Usage Guide

SNMP sessions are managed by the SNMPManager class. This class is a singleton,
so there is always a single instance of it.

    import foosnmp
    sm = foosnmp.SNMPManager()

The SNMPManager accepts the following optional parameters:

- name: the manager's name (defaults to "SNMPManager")
- log: callback function to use when logging SNMP messages. The callback must
  accept two parameters: priority and message.
- max_fd: maximum number of file descriptor to be used by the "select" stuff 
  (default is 1024)
- threaded_processor: set to True (default) if the asynchronous SNMP events
  processor must be executed in an independent thread. If False, the 
  "process_sessions" method must be called periodically.
- process_sessions_sleep: float specifying the number of seconds the "process_sessions"
  method must sleep after every loop (default is 0.01).
- local_dir: path to directory where persistent data (MIBs, etc.) is and will be
  stored. If not given (default is None), the module dir will be used.
  In the given path a directory named 'mibs' must be present: all default MIBs
  should be available here or you'll be presented with a lot of errors like 
  "error : Cannot find module (IP-MIB): At line 1 in (none)".
    
When the SNMPManager is not needed anymore, it should be destroyed using the 
'destroy' method.

## MIB management methods

- set_mib_dir(PATH_TO_MIB_DIR): sets the directory where MIB files should be searched.

- add_mib_dir(PATH_TO_MIB_DIR): adds a directory to the ones already defined, 
  where MIB files should be searched.
    
- add_mib_dir(PATH_TO_MIB_DIR): removes a directory from the ones searched for 
  MIB files.
    
- get_mib_dir(): returns the current directories searched for MIB files.

- read_mib(PATH_TO_MIB_FILE): reads into memory a MIB file.

- refresh_mibs(): reloads all MIB definitions in use.

## Sessions management methods

- add_session(name, version='1', **kargs): creates and opens a new SNMP session.
  The parameters are:
  - name: session unique name.
  - version: SNMP protocol version ('1', '2', '3', default is '1')
  - kargs: SNMP protocol specific session arguments. You can pass any valid session field here.
    Commonly used, for versions '1' and '2':
    - peername: hostname of the SNMP agent to be queried.
    - community: community string to use.
    - timeout: seconds before retry (default 1 second)
    - retries: number of retries before failure (default 5)
    
  Returns a Session object or raises an exception.
    
- add_trapd_session(name, peername, fileno=-1): creates an SNMP trap daemon session.
  TRAP MANAGEMENT IS NOT TESTED.
    
- remove_session(name): closes and removes the given section.

- find_session(sessid): returns the Session instance associated with the given
  session ID.
    
- snmp_manager_instance[SESSION_NAME]: returns the Session instance with the 
  given name.
    
## Session events

- bind(slot, uid, session, callback): binds a callback function to a session's
  event slot. The parameters are:
  - slot: slot name (see below).
  - uid: unique identifier used to reference the binding.
  - session: session name or None for all sessions.
  - callback: callback function to be called on event. The callback signature
    must be (slot, session_name, request_id, result).
        
- unbind(slot, uid, session=None): removes the binded callback. 
  The parameters are:
  - slot: slot name.
  - uid: binding unique ID, as specified in the 'bind' call.
  - session: session name or None for all sessions.
    
The available slots are:

- 'get': emitted when an async 'get' response arrives.
- 'getnext': emitted when an async 'getnext' response arrives.
- 'getbulk': emitted when an async 'getbulk' response arrives.
- 'set': emitted when an async 'set' response arrives.
- 'inform': trap management (NOT TESTED).
- 'trap': trap management (NOT TESTED).
- 'trap2': trap management (NOT TESTED).
- 'report': trap management (NOT TESTED).
- 'response': emitted on any response kind, exept for 'timeout'.
- 'timeout': emitted on request timeout. The assigned callback signature must be
  (slot, session_name, request_id).
    
## Session instances

- get_description(oid, width=80, buffer_size=10240): returns an OID's description
  from the MIB file. The parameters are:
  - oid: oid name or oid tuple.
  - width: formatting width of the returned description. The default value (80)
    should be almost always right.
  - buffer_size: size of the buffer where the description is stored. The default
    value (80) should be almost always right.
        
- sync_get(oids, exc_on_error=False): performs a synchronous 'get' request for
  given oids. The parameters are:
  - oids: list of oid names or tuples.
  - exc_on_error: True to rise an exception if request fails (default is False).
    
- sync_getbulk(nonrepeaters, maxrepetitions, oids, exc_on_error=False): performs
  a synchronous 'getbulk' for given oids. The parameters are:
  - nonrepeaters: number of non repeaters.
  - maxrepetitions: maximum repetitions.
  - oids: list of oid names or tuples.
  - exc_on_error: True to rise an exception if request fails (default is False).
    
- sync_walk(root, exc_on_error=False): performs a synchronous 'getnext' request
  for the given oid. The parameters are:
  - oids: oid name or tuple.
  - exc_on_error: True to rise an exception if request fails (default is False).
    
- sync_set(oids_values, exc_on_error=False): performs a synchronous 'set' request
  for the given oids. The parameters are:
  - oids: list of (oid name or tuple, value to set) tuples (or lists).
  - exc_on_error: True to rise an exception if request fails (default is False).
    
- async_get(oids, wait=False, exc_on_error=False): performs an asynchronous 'get'
  request for given oids. The parameters are:
  - oids: list of oid names or tuples.
  - wait: used to make async calls sync, MUST not be used and left to FALSE.
  - exc_on_error: True to rise an exception if request fails (default is False).
    
- async_getbulk(nonrepeaters, maxrepetitions, oids, wait=False, exc_on_error=False):
  performs an asynchronous 'getbulk' for given oids. The parameters are:
  - nonrepeaters: number of non repeaters.
  - maxrepetitions: maximum repetitions.
  - oids: list of oid names or tuples.
  - wait: used to make async calls sync, MUST not be used and left to FALSE.
  - exc_on_error: True to rise an exception if request fails (default is False).
    
- async_walk(root, wait=False, exc_on_error=False): performs an asynchronous 
  'getnext' request for the given oid. The parameters are:
  - oids: oid name or tuple.
  - wait: used to make async calls sync, MUST not be used and left to FALSE.
  - exc_on_error: True to rise an exception if request fails (default is False).
    
- async_set(oids_values, wait=False, exc_on_error=False): performs an asynchronous
  'set' request for the given oids. The parameters are:
  - oids: list of (oid name or tuple, value to set) tuples (or lists).
  - wait: used to make async calls sync, MUST not be used and left to FALSE.
  - exc_on_error: True to rise an exception if request fails (default is False).
    
## Utilities

- str_to_oid(s): converts a string to an oid tuple.

- strs_to_oids(l): converts a list of strings to a list of oid tuples.

- oid_to_str(oid): converts an oid tuple to string.

- oids_to_strs(l): converts a list of oid tuples to a list of strings.

- oid_to_dot(oid): converts an oid to a "dotted" string.

- oids_to_dots(): converts a list of oids to a list of "dotted" strings.

