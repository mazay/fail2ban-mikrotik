#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import urllib
import gzip
import StringIO
import logging
import logging.handlers
import MySQLdb
import MySQLdb.cursors
import ConfigParser
import pygeoip
from datetime import datetime
from sys import exit
from optparse import OptionParser


def main(config, logger, ip_addr, attack_type, GEOIP_DAT):
    url = urllib.urlopen('http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz')
    url_f = StringIO.StringIO(url.read())
    handle = gzip.GzipFile(fileobj=url_f)
    with open(GEOIP_DAT, 'w') as out:
        for line in handle:
            out.write(line)

    if config.has_option('general', 'mysql_ip') and config.has_option('general', 'mysql_user') \
            and config.has_option('general', 'mysql_password') and config.has_option('general', 'mysql_db'):
        try:
            logger.info("Connecting to MySQL host: %s" % config.get('general', 'mysql_ip'))
            db = MySQLdb.connect(
                host=config.get('general', 'mysql_ip'),
                user=config.get('general', 'mysql_user'),
                passwd=config.get('general', 'mysql_password'),
                db=config.get('general', 'mysql_db'),
                cursorclass=MySQLdb.cursors.DictCursor
            )

            cursor = db.cursor()
            logger.debug("Connected")
        except MySQLdb.Error, e:
            logger.error("Error %d: %s" % (e.args[0], e.args[1]))
            exit(2)
        else:
            query = """select * from ban_history where ip_address='%s' and type='%s'""" % (ip_addr, attack_type)
            result = run_query(cursor, query, logger)
            result = cursor.fetchall()
            now = datetime.now()
            gi = pygeoip.GeoIP(GEOIP_DAT, flags=pygeoip.const.MEMORY_CACHE)
            country_code = gi.country_code_by_addr(ip_addr)
            country_name = gi.country_name_by_addr(ip_addr)
            if len(result) > 0:
                logger.info("Updating blacklist DB record for IP-address %s" % ip_addr)
                result = result[0]
                count = result['count'] + 1
                query = """update ban_history set count=%s, last_attempt='%s', 
                        country_code='%s', country_name='%s' where id=%s""" % (
                    count, now, country_code, country_name, result['id']
                )
                result = run_query(cursor, query, logger)
                db.commit()
            else:
                logger.info("Adding IP-address %s into blacklist DB" % ip_addr)
                count = 1
                query = """insert into ban_history (ip_address, country_code, country_name, count, type, 
                        last_attempt, first_attempt) values('%s', '%s', '%s', %s, '%s', '%s', '%s')""" % (
                    ip_addr, country_code, country_name, count, attack_type, now, now
                )
                result = run_query(cursor, query, logger)
                db.commit()

    else:
        logger.error("Configuration incomplete")
        exit(3)


def run_query(cursor, query, logger):
    try:
        logger.debug("Running query \'%s\'" % query)
        cursor.execute(query)
    except MySQLdb.Error, e:
        logger.error("Error %d: %s" % (e.args[0], e.args[1]))
        exit(2)
    else:
        return True


if __name__ == '__main__':
    try:
        ROOT_PATH = os.path.dirname(os.path.realpath(__file__))
        GEOIP_DAT = os.path.join(ROOT_PATH, 'GeoIP.dat')
        parser = OptionParser(usage="usage: %prog [-c <configuration_file>] [-v] --ip IP-ADDRESS --type TYPE")
        parser.add_option("-v", "--verbose",
                          action="store_true",
                          default=False,
                          dest="verbose",
                          help="Verbose output")
        parser.add_option("-c", "--config",
                          action="store",
                          default=False,
                          dest="cfg_file",
                          help="Full path to configuration file")
        parser.add_option("--ip",
                          action="store",
                          default=False,
                          dest="ip_addr",
                          help="Attacker IP address")
        parser.add_option("--type",
                          action="store",
                          default=False,
                          dest="attack_type",
                          help="Type of attack (service)")

        (options, args) = parser.parse_args()
        verbose = options.verbose

        ip_addr = options.ip_addr
        attack_type = options.attack_type

        # Reading configuration file
        cfg_file = options.cfg_file
        if not cfg_file:
            cfg_file = os.path.join(ROOT_PATH, 'blacklist_db.cfg')

        config = ConfigParser.RawConfigParser()
        config.read(cfg_file)

        # Logging
        if config.get('general', 'log_file'):
            LOGFILE = config.get('general', 'log_file')
        else:
            LOGFILE = '/var/log/blacklist_db.log'

        FORMAT = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        try:
            rotatetime = logging.handlers.TimedRotatingFileHandler(LOGFILE, when="midnight", interval=1, backupCount=14)
        except IOError, e:
            print "ERROR %s: Can not open log file - %s" % (e[0], e[1])
            exit(1)
        except Exception, e:
            print "Can not configure logger - %s" % e
            exit(1)

        formatter = logging.Formatter('%(asctime)s: %(message)s', '%y-%m-%d %H:%M:%S')

        rotatetime.setFormatter(FORMAT)
        logger = logging.getLogger('fail2ban-mikrotik')
        logger.addHandler(rotatetime)

        if verbose:
            lvl = logging.DEBUG
            console = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s: %(message)s', '%y-%m-%d %H:%M:%S')
            console.setFormatter(formatter)
            logger.addHandler(console)
        else:
            lvl = logging.INFO

        logger.setLevel(lvl)

        if ip_addr and attack_type:
            main(config, logger, ip_addr, attack_type, GEOIP_DAT)
        else:
            logger.error("IP address and attack type are needed but not specified")
            exit(1)

    except KeyboardInterrupt:
        logger.info("CTRL-C... exit")
        exit(0)

    except SystemExit:
        logger.info("Exit")
        exit(0)
