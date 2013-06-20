#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from lib.core.common import Backend
from lib.core.common import Format
from lib.core.common import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.session import setDbms
from lib.core.settings import HSQL_ALIASES
from lib.core.settings import UNKNOWN_DBMS_VERSION
from lib.request import inject
from plugins.generic.fingerprint import Fingerprint as GenericFingerprint

class Fingerprint(GenericFingerprint):
    def __init__(self):
        GenericFingerprint.__init__(self, DBMS.HSQL)

    def _commentCheck(self):
        infoMsg = "executing %s comment injection fingerprint" % DBMS.HSQL
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/* NoValue */")

        if not result:
            warnMsg = "unable to perform %s comment injection" % DBMS.HSQL
            logger.warn(warnMsg)

            return None

        # HSQL - TODO NOT UPDATED FROM MYSQL
        versions = (
                     (32200, 32235),    # HSQL 3.22
                     (32300, 32359),    # HSQL 3.23
                     (40000, 40032),    # HSQL 4.0
                     (40100, 40131),    # HSQL 4.1
                     (50000, 50092),    # HSQL 5.0
                     (50100, 50156),    # HSQL 5.1
                     (50400, 50404),    # HSQL 5.4
                     (50500, 50521),    # HSQL 5.5
                     (50600, 50604),    # HSQL 5.6
                     (60000, 60014),    # HSQL 6.0
                   )

        index = -1
        for i in xrange(len(versions)):
            element = versions[i]
            version = element[0]
            version = getUnicode(version)
            result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/*!%s AND [RANDNUM1]=[RANDNUM2]*/" % version)

            if result:
                break
            else:
                index += 1

        if index >= 0:
            prevVer = None

            for version in xrange(versions[index][0], versions[index][1] + 1):
                version = getUnicode(version)
                result = inject.checkBooleanExpression("[RANDNUM]=[RANDNUM]/*!%s AND [RANDNUM1]=[RANDNUM2]*/" % version)

                if result:
                    if not prevVer:
                        prevVer = version

                    if version[0] == "3":
                        midVer = prevVer[1:3]
                    else:
                        midVer = prevVer[2]

                    trueVer = "%s.%s.%s" % (prevVer[0], midVer, prevVer[3:])

                    return trueVer

                prevVer = version

        return None

    def getFingerprint(self):
        value = ""
        wsOsFp = Format.getOs("web server", kb.headersFp)

        if wsOsFp and not hasattr(conf, "api"):
            value += "%s\n" % wsOsFp

        if kb.data.banner:
            dbmsOsFp = Format.getOs("back-end DBMS", kb.bannerFp)

            if dbmsOsFp and not hasattr(conf, "api"):
                value += "%s\n" % dbmsOsFp

        value += "back-end DBMS: "
        actVer = Format.getDbms()

        if not conf.extensiveFp:
            value += actVer
            return value

        comVer = self._commentCheck()
        blank = " " * 15
        value += "active fingerprint: %s" % actVer

        if comVer:
            comVer = Format.getDbms([comVer])
            value += "\n%scomment injection fingerprint: %s" % (blank, comVer)

        if kb.bannerFp:
            banVer = kb.bannerFp["dbmsVersion"] if 'dbmsVersion' in kb.bannerFp else None

            if re.search("-log$", kb.data.banner):
                banVer += ", logging enabled"

            banVer = Format.getDbms([banVer] if banVer else None)
            value += "\n%sbanner parsing fingerprint: %s" % (blank, banVer)

        htmlErrorFp = Format.getErrorParsedDBMSes()

        if htmlErrorFp:
            value += "\n%shtml error message fingerprint: %s" % (blank, htmlErrorFp)

        return value

    def checkDbms(self):
        """
        References for fingerprint:

        
        """

        if not conf.extensiveFp and (Backend.isDbmsWithin(HSQL_ALIASES) \
           or conf.dbms in HSQL_ALIASES) and Backend.getVersion() and \
           Backend.getVersion() != UNKNOWN_DBMS_VERSION:
            v = Backend.getVersion().replace(">", "")
            v = v.replace("=", "")
            v = v.replace(" ", "")

            Backend.setVersion(v)

            setDbms("%s %s" % (DBMS.HSQL, Backend.getVersion()))

            if Backend.isVersionGreaterOrEqualThan("5"):
                kb.data.has_information_schema = True

            self.getBanner()

            return True

        infoMsg = "testing %s" % DBMS.HSQL
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("ROUNDMAGIC(PI())>=3")

        if result:
            infoMsg = "confirming %s" % DBMS.HSQL
            logger.info(infoMsg)

            result = inject.checkBooleanExpression("USER() LIKE USER()")

            if not result:
                warnMsg = "the back-end DBMS is not %s" % DBMS.HSQL
                logger.warn(warnMsg)

                return False

                if not conf.extensiveFp:
                    return True
                else:
                    Backend.setVersionList(["?", "?"])
            else:
                Backend.setVersion("v?")
                setDbms("%s 3" % DBMS.HSQL)
                self.getBanner()

            return True
        else:
            warnMsg = "the back-end DBMS is not %s" % DBMS.HSQL
            logger.warn(warnMsg)

            return False

    def checkDbmsOs(self, detailed=False):
        if Backend.getOs():
            return

        infoMsg = "fingerprinting the back-end DBMS operating system"
        logger.info(infoMsg)

        result = inject.checkBooleanExpression("'W'=UPPER(MID(@@version_compile_os,1,1))")

        if result:
            Backend.setOs(OS.WINDOWS)
        elif not result:
            Backend.setOs(OS.LINUX)

        if Backend.getOs():
            infoMsg = "the back-end DBMS operating system is %s" % Backend.getOs()
            logger.info(infoMsg)
        else:
            self.userChooseDbmsOs()

        self.cleanup(onlyFileTbl=True)
