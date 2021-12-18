import yaml
import logging
import os


class CFG:

    def get_logger(self, log_name, log_path=os.getcwd(), level=logging.INFO):
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

    def verify_config(self, config):
        for v in self.cfg[config].values():
            if not v:
                return False
        return True

    def load_config(self, config="config_lab.yml"):
        with open(config, 'r') as stream:
            try:
                self.cfg = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

    def __init__(self):
        self.cfg = None

