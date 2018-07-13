import os


class Config(object):
    SECRET_KEY = os.environ.get("SECRET_KEY") or "ItemCatalogSecret"
    ENV = "development"
    PORT = 8000
