# Copyright (c) 2007 D-Level s.r.l. - All rights reserved

# THIS TEST MUST BE EXECUTED FROM THE PARENT DIRECTORY (so the libs can be found)

# D-Level specific imports --------------------------------------------------

from DLevel.Utilities.Singleton import Singleton
from DLevel.Utilities.SymbolicConstants import NOT_GIVEN
from DLevel.Utilities.Threads.ThreadLocals import ThreadLocals
from DLevel.Utilities.Failure import Failure

#----------------------------------------------------------------------------

import os
import sys
import time
import pprint
import threading
import copy
import gc
import optparse

from DLNetSNMP import *

stdout = sys.stdout
stderr = sys.stderr
#from DLNetSNMP_CONSTANTS import *

#------------------------------------------------------------------------

import cStringIO
import operator

def indent (rows, hasHeader=False, headerChar='-', delim=' | ', justify='left',
	   separateRows=False, prefix='', postfix='', wrapfunc=lambda x:x):
	"""Indents a table by column.
	- rows: A sequence of sequences of items, one sequence per row.
	- hasHeader: True if the first row consists of the columns' names.
	- headerChar: Character to be used for the row separator line
	  (if hasHeader==True or separateRows==True).
	- delim: The column delimiter.
	- justify: Determines how are data justified in their column. 
	  Valid values are 'left','right' and 'center'.
	- separateRows: True if rows are to be separated by a line
	  of 'headerChar's.
	- prefix: A string prepended to each printed row.
	- postfix: A string appended to each printed row.
	- wrapfunc: A function f(text) for wrapping text; each element in
	  the table is first wrapped by this function."""
	# closure for breaking logical rows to physical, using wrapfunc
	def rowWrapper(row):
		newRows = [wrapfunc(item).split('\n') for item in row]
		return [[substr or '' for substr in item] for item in map(None,*newRows)]
	# break each logical row into one or more physical ones
	logicalRows = [rowWrapper(row) for row in rows]
	# columns of physical rows
	columns = map(None,*reduce(operator.add,logicalRows))
	# get the maximum of each column by the string length of its items
	maxWidths = [max([len(str(item)) for item in column]) for column in columns]
	rowSeparator = headerChar * (len(prefix) + len(postfix) + sum(maxWidths) + \
				     len(delim)*(len(maxWidths)-1))
	# select the appropriate justify method
	justify = {'center':str.center, 'right':str.rjust, 'left':str.ljust}[justify.lower()]
	output=cStringIO.StringIO()
	if separateRows: print >> output, rowSeparator
	for physicalRows in logicalRows:
		for row in physicalRows:
			print >> output, \
			    prefix \
			    + delim.join([justify(str(item),width) for (item,width) in zip(row,maxWidths)]) \
			    + postfix
		if separateRows or hasHeader: print >> output, rowSeparator; hasHeader=False
	return output.getvalue()

#------------------------------------------------------------------------

class DLNetSNMPTest (object):
	def __init__ (self, hostname='localhost', version='2', public='public', private='private', verbose=True, timeout=None):
		self.hostname = hostname
		self.version = version
		self.public = public
		self.private = private
		self.verbose = verbose
		self.timeout = timeout
		self.locals = ThreadLocals ()
		self.sessions = {}
		self.threads = []
		self.rlock = threading.RLock ()
		self.async_results = {}
		
		self.init_manager (self)
		self.public_session = self.init_session (self.manager, 'public', False)
		self.private_session = self.init_session (self.manager, 'private', True)
		self.trapd_session = self.manager.add_session (
			name = 'trapd',
			peername = self.hostname,
		)
		
	def destroy (self):
		for t in self.threads:
			if t.isAlive ():
				print '# JOINING THREAD %s' % t.getName ()
				t.join (1)
				if t.isAlive ():
					print '# THREAD %s STILL ALIVE!' % t.getName ()
		self.threads = None
		
		self.public_session = None
		self.private_session = None
		self.trapd_session = None
		
		self.destroy_manager (self)
		
		self.sessions.clear ()
		self.locals = None
		
	#------------------------------------------------------------------------
	
	def run_tests (self, config={}):
		if not isinstance (config, (tuple, list)):
			config = [config]
			
		for c in config:
			name = c.get ('name', '')
			test = getattr (self, 'test_' + name, None)
			if not test:
				self.log ('INVALID TEST NAME: %(name)s', name=name, section='!')
				continue
			
			repeats = c.get ('repeats', 1)
			threaded = c.get ('threaded', False)
			private = c.get ('private', False)
			args = list (c.get ('args', []))
			kargs = c.get ('kargs', {})
			
			if threaded:
				for n in range (repeats):
					if repeats == 1:
						step = ''
					else:
						step = ' (%s/%s)' % (n + 1, repeats)
						
					def target (name, test, step, private, args, kargs):
						l_args = copy.deepcopy (args)
						l_kargs = copy.deepcopy (kargs)
						s_name = '%s_%s' % (name, id (threading.currentThread ()))
						
						s = self.init_session (self.manager, s_name, private=private)
						
						l_kargs['manager'] = self.manager
						l_kargs['session'] = s
						
						try:
							test (step=step, *l_args, **l_kargs)
						finally:
							self.destroy_session (s_name)
					
					t = threading.Thread (name=name, target=target, args=[name, test, step, private, args, kargs])
					t.setDaemon (True)
					self.threads.append (t)
					t.start ()
					self.log ('Thread %(name)s (%(tid)s) started', name=name, tid=t.getThreadID (), section='&')
			else:
				kargs['manager'] = self.manager
				kargs['session'] = private and self.private_session or self.public_session
				self.repeat_test (repeats, test, *args, **kargs)
			
	#------------------------------------------------------------------------
	
	def log (self, message, indent=0, section='', step='', **kargs):
		if self.verbose:
			self.rlock.acquire ()
			try:
				n = (indent * 4)
				i = ' ' * n
				if section:
					print i + section * (78 - n)
				
				txt = message % kargs
				txt = txt + step
				
				for l in txt.split ('\n'):
					print i + l
			finally:
				self.rlock.release ()
			
	def dump_result (self, r, indent=1):
		if isinstance (r, dict):
			for k, v in r.iteritems ():
				try:
					self.log ('%(oid_str)s (%(oid)s) = %(value)s', oid_str=oid_to_str (k), oid=k, value=v, indent=indent)
				except:
					exc = Failure ().get_brief_traceback ()
					self.log ('%(oid)s ERROR: %(exc)s', oid=k, exc=exc, indent=indent)
		elif isinstance (r, (int, long)):
			self.log ('ASYNC REQUEST STARTED: %(data)r', data=r, indent=indent)
		else:
			self.log ('ERROR: expected dict result, received %(data)r', data=r, indent=indent)
			
	def repeat_test (self, n, test, *args, **kargs):
		for s in range (n):
			if n == 1:
				step = ''
			else:
				step = ' (%s/%s)' % (s + 1, n)
				
			test (step=step, *args, **kargs)
			
	#------------------------------------------------------------------------
	
	def init_manager (self, storage):
		local_dir = os.path.abspath (os.path.join (os.path.basename (__file__), '..', '..', '..'))
		storage.manager = SNMPManager (local_dir=local_dir)
		storage.manager.bind ('get', id (storage), None, self.result_cb)
		storage.manager.bind ('getnext', id (storage), None, self.result_cb)
		storage.manager.bind ('getbulk', id (storage), None, self.result_cb)
		storage.manager.bind ('set', id (storage), None, self.result_cb)
		storage.manager.bind ('timeout', id (storage), None, self.timeout_cb)
		storage.manager.bind ('trap', id (storage), None, self.result_cb)
		storage.manager.bind ('trap2', id (storage), None, self.result_cb)
		storage.manager.bind ('inform', id (storage), None, self.result_cb)
		
	def destroy_manager (self, storage):
		storage.manager.destroy ()
		storage.manager = None
		
	def init_session (self, manager, name, private=False):
		if private:
			pw = self.private
		else:
			pw = self.public
			
		s = manager.add_session (
			name = name,
			version = self.version,
			peername = self.hostname,
			community = pw,
			timeout = self.timeout
		)
		self.sessions[name] = s
		return s
	
	def destroy_session (self, name):
		s = self.sessions[name]
		del self.sessions[name]
		if s.manager:
			s.manager.remove_session (name)

	#------------------------------------------------------------------------
	
	def timeout_cb (self, manager, slot, session, reqid):
		self.log ('* ASYNC TIMEOUT "%(slot)s" %(uid)s', slot=slot, uid=(manager, session, reqid))
		
	def result_cb (self, manager, slot, session, reqid, r):
		self.log ('* ASYNC RESULT "%(slot)s" %(uid)s', slot=slot, uid=(manager, session, reqid), section='~')
		self.dump_result (r)
		self.async_results[slot] = self.async_results.setdefault (slot, 0) + 1
		
	#------------------------------------------------------------------------
	
	def test_read_mib (self, manager, session, path, step=''):
		self.log ('READ MIB', section='=', step=step)
		b = manager.read_mib (path)
		self.log ('Result: %(result)s', result=b, indent=1)
		
	def test_add_mib_dir (self, manager, session, path, step=''):
		self.log ('ADD MIB DIR', section='=', step=step)
		manager.add_mib_dir (path)
		manager.refresh_mibs ()
		self.log ('Mib dirs: %(result)s', result=manager.get_mib_dir (), indent=1)
		
	def test_get_descriptions (self, manager, session, mibs, step=''):
		self.log ('GET DESCRIPTIONS', section='=', step=step)
		for i in mibs:
			self.log ('MIB: %(mib)s', mib=i, indent=1, section='-')
			self.log ('str_to_oid: %(data)s', data=str_to_oid (i), indent=1)
			self.log ('oid_to_str: %(data)s', data=oid_to_str (str_to_oid (i)), indent=1)
			self.log ('get_oid_info:', indent=1)
			self.log ('%(data)s', data=pprint.pformat (get_oid_info (i)), indent=2)
			self.log ('get_description:', indent=1)
			self.log ('%(data)s', data=session.get_description (i), indent=2)
		
	#------------------------------------------------------------------------
	
	def test_sync_get (self, manager, session, mibs, step=''):
		self.log ('SYNC GET', section='=', step=step)
		r = session.sync_get (mibs)
		self.dump_result (r)
		
	def test_sync_getbulk (self, manager, session, mibs, nonrepeaters=0, maxrepetitions=10, step=''):
		self.log ('SYNC GETBULK', section='=', step=step)
		r = session.sync_getbulk (nonrepeaters, maxrepetitions, mibs)
		self.dump_result (r)
		
	def test_sync_walk (self, manager, session, start, count, step=''):
		oid = start
		self.log ('SYNC WALK [root = %(root)s]', root=oid_to_str (oid), section='=', step=step)
		for i in range (count):
			r = session.sync_walk (oid)
			#self.dump_result (r)
			if r:
				try:
					t_oid = r.popitem ()[0]
					if t_oid <= oid:
						break
					oid = t_oid
				except:
					self.log ('Wrong result %(result)r', result=r, indent=1)
			else:
				self.log ('Not enouth IODs', indent=1)
				break
		
	def test_sync_set (self, manager, session, mibs_values, step=''):
		self.log ('SYNC SET', section='=', step=step)
		
		if isinstance (mibs_values, dict):
			mibs_values = mibs_values.items ()
		mibs = [i[0] for i in mibs_values]
		
		current_values = session.sync_get (mibs)
		r = session.sync_set (mibs_values)
		self.dump_result (r)
		set_values = dict (mibs_values)
		new_values = session.sync_get (mibs)
		
		rows = []
		for k, v in set_values.iteritems ():
			try:
				oid = tuple (str_to_oid (k))
				if isinstance (current_values, dict):
					cv = current_values.get (oid, 'UNKNOWN')
				else:
					cv = 'ERR'
					
				if isinstance (new_values, dict):
					nv = new_values.get (oid, 'UNKNOWN')
				else:
					nv = 'ERR'
					
				rows.append ((k, cv, v, nv))
			except:
				Failure ().print_brief_traceback ()
		labels = ('OID', 'Before', 'Set', 'After')
		t = indent ([labels] + rows, hasHeader=True)
		self.log ('%(table)s', table=t, indent=1)
		
	#------------------------------------------------------------------------
	
	def test_async_get (self, manager, session, mibs, step=''):
		self.log ('ASYNC GET', section='=', step=step)
		r = session.async_get (mibs)
		self.dump_result (r)
		
	def test_async_getbulk (self, manager, session, mibs, nonrepeaters=0, maxrepetitions=10, step=''):
		self.log ('ASYNC GETBULK', section='=', step=step)
		r = session.async_getbulk (nonrepeaters, maxrepetitions, mibs)
		self.dump_result (r)
		
	def test_async_walk (self, manager, session, start, count, step=''):
		oid = start
		self.log ('ASYNC WALK [root = %(root)s]', root=oid_to_str (oid), section='=', step=step)
		for i in range (count):
			r = session.async_walk (oid)
			self.dump_result (r)
			#if r:
				#oid = r.popitem ()[0]
			#else:
				#self.log ('Not enouth IODs', indent=1)
				#break
		

#------------------------------------------------------------------------

WRONG_DATA_PATH = os.path.abspath (os.path.join (os.path.basename (__file__), 'test', 'data'))
DATA_PATH = os.path.abspath (os.path.join (os.path.basename (__file__), '..', 'test', 'data'))
MIB_FILE = 'LINKSYS.MIB'
OIDS = [
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

CONFIG = [
	{
		'name': 'add_mib_dir',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'path': DATA_PATH,
		},
	},
	{
		'name': 'read_mib',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'path': os.path.join (DATA_PATH, MIB_FILE),
		},
	},
	{
		'name': 'get_descriptions',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'mibs': OIDS,
		},
	},
	
	#-----------------------------------------------------------------------
	
	{
		'name': 'sync_get',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'mibs': OIDS,
		},
	},
	{
		'name': 'sync_getbulk',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'mibs': OIDS,
		},
	},
	{
		'name': 'sync_walk',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'start': 'SNMPv2-MIB::sysObjectID.0',
			'count': 20,
		},
	},
	{
		'name': 'sync_set',
		'threaded': False,
		'repeats': 1,
		'private': True,
		'args': [],
		'kargs': {
			'mibs_values': [('sysLocation.0', 'Plaino')],
		},
	},
	
	#-----------------------------------------------------------------------
	
	{
		'name': 'async_get',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'mibs': OIDS,
		},
	},
	{
		'name': 'async_getbulk',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'mibs': OIDS,
		},
	},
	{
		'name': 'async_walk',
		'threaded': False,
		'repeats': 1,
		'private': False,
		'args': [],
		'kargs': {
			'start': 'SNMPv2-MIB::sysObjectID.0',
			'count': 3,
		},
	},
	
]

def set_config_params (config, **kargs):
	new_config = copy.deepcopy (config)
	for c in new_config:
		for k, v in kargs.items ():
			c[k] = v
	return new_config

def get_options ():
	parser = optparse.OptionParser (version='1.0', prog='test_dlnetsnmp')

	parser.add_option (
		'-v',
		"--verbose",
		action = 'store_true',
		dest = 'verbose',
		default = True,
		help = "Be moderately verbose (default %default)."
	)
	parser.add_option (
		'-t',
		"--threaded",
		action = 'store_true',
		dest = 'threaded',
		default = False,
		help = "Run tests in separated threads (default %default)."
	)

	parser.add_option (
		'-r',
		"--repeats",
		type = "int",
		dest = 'repeats',
		default = 1,
		help = "Number of times to repeat each test (default %default)."
	)

	parser.add_option (
		'-s',
		"--sleep",
		type = "int",
		dest = 'sleep',
		default = 1,
		help = "Number of seconds to wait before exiting the test program (default %default)."
	)
	parser.add_option (
		'-o',
		"--timeout",
		type = "int",
		dest = 'timeout',
		default = 1,
		help = "Number of seconds before session times out (default %default)."
	)

	parser.add_option (
		'-n',
		"--hostname",
		type = "string",
		dest = 'hostname',
		default = 'localhost',
		help = "SNMP server hostname (default %default)."
	)
	parser.add_option (
		'-p',
		"--protocol",
		type = "string",
		dest = 'protocol',
		default = '2',
		help = "SNMP protocol version (default %default)."
	)
	parser.add_option (
		'',
		"--public",
		type = "string",
		dest = 'public',
		default = 'public',
		help = "SNMP server public community string (default %default)."
	)
	parser.add_option (
		'',
		"--private",
		type = "string",
		dest = 'private',
		default = 'private',
		help = "SNMP server private community string (default %default)."
	)
	parser.add_option (
		'',
		"--community",
		type = "string",
		dest = 'community',
		default = 'public',
		help = "SNMP server community to use in tests (default %default)."
	)

	parser.add_option (
		'-g',
		"--garbage",
		action = 'store_true',
		dest = 'garbage',
		default = False,
		help = "Print garbage collector debug info (default %default)."
	)
	
	return parser

def print_garbage ():
	print '#'*78
	print 'GARBAGE'
	gc.collect ()
	for i in gc.garbage:
		print '    ', '-'*74
		print '    ', type (i), id (i), pprint.pformat (i)
		print '    ', 'REFERRERS:', gc.get_referrers (i)
		print '    ', 'REFERENTS:', gc.get_referents (i)

def main ():
	parser = get_options ()
	options = parser.parse_args ()[0]
	
	if options.garbage:
		gc.set_debug (gc.DEBUG_LEAK)

	test = DLNetSNMPTest (
		hostname = options.hostname, 
		version = options.protocol,
		public = options.public,
		private = options.private,
		verbose = options.verbose,
		timeout = options.timeout,
	)
	c = set_config_params (
		CONFIG, 
		threaded = options.threaded,
		repeats = options.repeats,
		private = options.community == 'private',
	)
	test.run_tests (c)
	r = pprint.pformat (test.async_results)
	time.sleep (options.sleep)
	print 'PENDING REQUESTS', [len (i.async_requests) for i in test.sessions.values ()]
	print 'ASYNC RESULTS:', r, pprint.pformat (test.async_results)
	test.destroy ()
	
	if options.garbage:
		del options
		del parser
		print_garbage ()
		
if __name__ == '__main__':
	main ()
	