from flask_script import Manager

from hello import app,db

import os

from config import Config

from flask_migrate import Migrate,MigrateCommand

from flask import Flask

from flask_sqlalchemy import SQLAlchemy


app.config.from_object(Config)

migrate = Migrate(app, db)

manager = Manager(app)

manager.add_command('db', MigrateCommand)

if __name__ == '__main__':

    manager.run()