#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

try:
    import jpype
    from thirdparty import jaydebeapi
except ImportError, msg:
    pass

import logging

from lib.core.data import conf
from lib.core.data import logger
from lib.core.exception import SqlmapConnectionException
from plugins.generic.connector import Connector as GenericConnector

class Connector(GenericConnector):
    """
    Homepage: http://jpype.sourceforge.net/
    User guide: http://jpype.sourceforge.net/doc/user-guide/userguide.html
    API: http://code.google.com/p/pymysql/
    Debian package: <none>
    License: Apache License V2.0
    """

    def __init__(self):
        GenericConnector.__init__(self)

    def connect(self):
        self.initConnection()

        try:
            jar = './thirdparty/hsql/hsqldb.jar'
            args='-Djava.class.path=%s' % jar
            jvm_path = jpype.getDefaultJVMPath()
            jpype.startJVM(jvm_path, args)
        except (Exception), msg: #todo fix with specific error
            raise SqlmapConnectionException(msg[1])
        try:
            driver = 'org.hsqldb.jdbc.JDBCDriver'
            connection_string = 'jdbc:hsqldb:hsql://localhost/xdb'#'jdbc:hsqldb:hsql://%s/%s' % (self.hostname, 'xdb')
            self.connector = jaydebeapi.connect(driver,
                                        connection_string,
                                        self.user,
                                        self.password)
        
        except (Exception), msg: #todo what kind of error is this?!
            raise SqlmapConnectionException(msg[0])

        self.initCursor()
        self.printConnected()

    def fetchall(self):
        try:
            return self.cursor.fetchall()
        except (Exception), msg:
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
            return None

    def execute(self, query):
        retVal = False

        try:
            self.cursor.execute(query)
            retVal = True
        except (Exception), msg: #todo fix with specific error
            logger.log(logging.WARN if conf.dbmsHandler else logging.DEBUG, "(remote) %s" % msg[1])
        except Exception, msg: #todo fix with specific error
            raise SqlmapConnectionException(msg[1])

        self.connector.commit()

        return retVal

    def select(self, query):
        retVal = None

        print str(self.cursor)
        self.cursor.execute(query)
        retVal = self.cursor.fetchall()

        return retVal
