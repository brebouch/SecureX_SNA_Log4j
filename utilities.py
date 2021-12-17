import yaml
import logging
import os


def get_logger(log_name, log_path=os.getcwd(), level=logging.INFO):
    logFormatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    rootLogger = logging.getLogger()
    path = os.path.join(log_path, log_name)

    fileHandler = logging.FileHandler("{0}.log".format(path))
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)
    rootLogger.setLevel(level)
    return rootLogger

def verify_config(config):
    for v in cfg[config].values():
        if not v:
            return False
    return True


with open("config.yml", 'r') as stream:
    try:
        cfg = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
