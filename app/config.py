import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # SQLite DB file in project root (same level as wsgi.py)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///bliztech.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
