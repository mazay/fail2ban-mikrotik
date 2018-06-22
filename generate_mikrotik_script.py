#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import logging
import logging.handlers
import MySQLdb
import MySQLdb.cursors
import ConfigParser
from sys import exit
from optparse import OptionParser


def main(config, logger, output):
    if config.has_option('general', 'ban_count'):
        ban_count = config.getint('general', 'ban_count')
    else:
        ban_count = 10

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
            contents = ['/ip firewall address-list']
            logger.info('Fetching adresses from the blacklist DB')
            query = """select * from ban_history"""
            result = run_query(cursor, query, logger)
            result = cursor.fetchall()
            for ip in result:
                if ip['count'] >= ban_count:
                    list_name = '%s_BLC' % ip['type'].upper()
                    logger.info('Adding IP %s into \'%s\' list' % (ip['ip_address'], list_name))
                    list_line = 'add address=%s list=%s comment=BLACKLIST' % (ip['ip_address'], list_name)
                    contents.append(list_line)

            if len(contents) > 1:
                logger.info('Generating mikrotik rsc script...')
                script_file = open(output, 'w')
                for item in contents:
                    script_file.write("%s\r\n" % item)

                script_file.close()

            logger.info('Done')

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
        parser = OptionParser(usage="usage: %prog [-c <configuration_file>] [-v] [-o <output_file_path>]")
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
        parser.add_option("-o",
                          action="store",
                          default=False,
                          dest="output",
                          help="Full path for the generated script file")

        (options, args) = parser.parse_args()
        verbose = options.verbose
        output = options.output

        if not output:
            output = os.path.join(ROOT_PATH, 'blacklists.rsc')

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
            LOGFILE = '/tmp/blacklist_db.log'

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

        main(config, logger, output)

    except KeyboardInterrupt:
        logger.info("CTRL-C... exit")
        exit(0)

    except SystemExit:
        logger.info("Exit")
        exit(0)
