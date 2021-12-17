import yaml


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
