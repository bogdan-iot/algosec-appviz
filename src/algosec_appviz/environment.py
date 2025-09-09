import logging
import os
import pathlib
import sys
from dotenv import load_dotenv

# Get environment variables from local .env file and user's home directory .env file
dotenv_current_path = os.path.join(pathlib.Path().resolve(), '.env')
dotenv_home_path = os.path.join(pathlib.Path.home().resolve(), '.env')
load_dotenv(dotenv_home_path)
load_dotenv(dotenv_current_path)

# Logging config
if sys.version_info.major >= 3 and sys.version_info.minor >= 9:
    logging.basicConfig(filename='algosec_appviz.log',
                        encoding='utf-8',
                        level=logging.INFO,
                        format='%(levelname)s:%(asctime)s %(message)s',
                        datefmt='%d/%m/%Y %H:%M:%S')
else:
    logging.basicConfig(filename='algosec_appviz.log',
                        level=logging.INFO,
                        format='%(levelname)s:%(asctime)s %(message)s',
                        datefmt='%d/%m/%Y %H:%M:%S')

# GENERAL SETTINGS
VERBOSE = False
if 'VERBOSE' in os.environ and (
        os.environ["VERBOSE"].lower() == "true"
        or os.environ["VERBOSE"].lower() == "yes"
        or os.environ["VERBOSE"] == 1):
    VERBOSE = True

DEBUG = False
if 'DEBUG' in os.environ and (
        os.environ["DEBUG"].lower() == "true"
        or os.environ["DEBUG"].lower() == "yes"
        or os.environ["DEBUG"] == 1):
    DEBUG = True


def get_tenant_id():
    """Get the AppViz tenant ID from environment variables"""
    return os.environ.get("APPVIZ_TENANT_ID")


def get_client_id():
    """Get the AppViz client ID from environment variables"""
    return os.environ.get("APPVIZ_CLIENT_ID")


def get_client_secret():
    """Get the AppViz client secret from environment variables"""
    return os.environ.get("APPVIZ_CLIENT_SECRET")
