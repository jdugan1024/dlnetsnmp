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

from threading import RLock


def is_instance_func(cls):
    cls.mutex.acquire()
    try:
        return hasattr(cls, "__singleton__")
    finally:
        cls.mutex.release()


class MetaSingleton(type):
    def __init__(self, *args, **kargs):
        self.mutex = RLock()
        return type.__init__(self, *args, **kargs)


class Singleton(object):
    """Singleton pattern implementation.
	
	Objects derived from this class will have a single instance,
	no matter how many time their constructors are called.
	"""
    __metaclass__ = MetaSingleton

    def __new__(cls, *args, **kargs):
        cls.mutex.acquire()
        try:
            s = cls.__dict__.get("__singleton__", None)
            if s is not None:
                return s
            cls.__singleton__ = s = object.__new__(cls)
            s.__destroyed = False
            s.init_class(*args, **kargs)
            return s
        finally:
            cls.mutex.release()

    def __init__(self, *args, **kargs):
        pass

    def init_class(self, *args, **kargs):
        """Class initialization method.
		
		Called only the first time the singleton's constructor
		is called.
		
		@param args: list of arguments.
		
		@param kargs: dictionary with arguments.
		"""
        pass

    def destroy(self):
        if '__singleton__' in self.__class__.__dict__:
            delattr(self.__class__, '__singleton__')
        self.__destroyed = True

    def __get_destroyed(self):
        return self.__destroyed

    destroyed = property(__get_destroyed)

    def __repr__(self):
        return '<%s@%d ()>' % (self.__class__.__name__, id(self))

    is_instance = classmethod(is_instance_func)
    # for compatibilty
    instantiated = is_instance
