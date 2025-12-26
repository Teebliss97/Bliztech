# BlizTech Cyber Awareness Platform

A Flask-based cybersecurity awareness learning platform where users read topics, take quizzes, track progress, and unlock the next module.

## Features
- User registration & login
- Topic + quiz flow (unlock next topic after passing)
- Progress tracking (stored in database)
- Deployed on Render

## Tech Stack
- Flask, Jinja Templates
- Flask-Login, Flask-SQLAlchemy
- Flask-Migrate (Alembic)
- PostgreSQL (Render)

## Local Setup
1. Create a virtualenv and install requirements:
   pip install -r requirements.txt
2. Create a `.env` file:
   SECRET_KEY=your_secret
   DATABASE_URL=sqlite:///bliztech.db
3. Run:
   flask run

## Deployment
Deployed on Render: https://bliztech.onrender.com
