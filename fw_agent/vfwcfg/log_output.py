#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import logging
from logging import Logger
#import traceback
from logging.handlers import RotatingFileHandler

all_log_path = '/var/log/fw-agent.log'
err_log_path = '/var/log/fw-agent-error.log'

log_format = '%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'

__logger = logging.getLogger()
__logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')

all_logger_handler = RotatingFileHandler(filename=all_log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
all_logger_handler.setFormatter(formatter)
all_logger_handler.setLevel(level=logging.INFO)

err_logger_handler = RotatingFileHandler(filename=err_log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
err_logger_handler.setFormatter(formatter)
err_logger_handler.setLevel(level=logging.ERROR)

__logger.addHandler(all_logger_handler)
__logger.addHandler(err_logger_handler)

from .log_output import __logger as output

#class HandleLog(Logger):
#    def __init__(self, level='info'):
#        self.__all_log_path = all_log_path
#        self.__err_log_path = err_log_path
#
#        self.__logger = logging.getLogger()
#        self.__logger.setLevel(logging.DEBUG)
#
#        if level == 'debug':
#            self.__log_level = logging.DEBUG
#        elif level == 'info':
#            self.__log_level = logging.INFO
#        elif level == 'warning':
#            self.__log_level = logging.WARNING
#        elif level == 'error':
#            self.__log_level = logging.ERROR
#        elif level == 'critical':
#            self.__log_level = logging.CRITICAL
#        else:
#            self.__log_level = logging.INFO
#
#        all_logger_handler   = self.__init_logger_handler(self.__all_log_path)
#        err_logger_handler = self.__init_logger_handler(self.__err_log_path)
#
#        self.__set_log_handler(all_logger_handler, self.__log_level)
#        self.__set_log_handler(err_logger_handler, level=logging.ERROR)
#
#    @staticmethod
#    def __init_logger_handler(log_path):
#        logger_handler = RotatingFileHandler(filename=log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
#        return logger_handler
#
#    def __set_log_handler(self, logger_handler, level=logging.DEBUG):
#        # set log format
#        formatter = logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S')
#        logger_handler.setFormatter(formatter)
#
#        logger_handler.setLevel(level=level)
#        self.__logger.addHandler(logger_handler)
#
#    @staticmethod
#    def __close_handler(logger_handler):
#        logger_handler.close()
#
#    def __console(self, level, message):
#        #all_logger_handler   = self.__init_logger_handler(self.__all_log_path)
#        #err_logger_handler = self.__init_logger_handler(self.__err_log_path)
#
#        #self.__set_log_handler(all_logger_handler, self.__log_level)
#        #self.__set_log_handler(err_logger_handler, level=logging.ERROR)
#
#        if level == 'info':
#            self.__logger.info(message)
#        elif level == 'debug':
#            self.__logger.debug(message)
#        elif level == 'warning':
#            self.__logger.warning(message)
#        elif level == 'error':
#            #traceback.print_stack()
#            self.__logger.error(message)
#        elif level == 'critical':
#            self.__logger.critical(message)
#        else:
#            self.__logger.info(message)
#
#        #self.__logger.removeHandler(all_logger_handler)
#        #self.__logger.removeHandler(error_logger_handler)
#
#        #self.__close_handler(all_logger_handler)
#        #self.__close_handler(error_logger_handler)
#
#    #def debug(self, message):
#    #    self.__console('debug', message)
#
#    def info(self, message):
#        self.__console('info', message)
#
#    def warning(self, message):
#        self.__console('warning', message)
#
#    def error(self, message):
#        self.__console('error', message)
#
#    def critical(self, message):
#        self.__console('critical', message)
#
#
#output = HandleLog(level='debug')

#from .log_output import output
