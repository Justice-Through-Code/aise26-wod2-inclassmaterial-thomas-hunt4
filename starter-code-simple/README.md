# User Management API — Starter Code (Students)

⚠️ **EDUCATIONAL PURPOSE**: This code contains intentional security vulnerabilities for learning. Do NOT use in production.

## Overview
Basic Flask API for user management. Your task is to transform this into a secure, professionally configured repository in your own repo.

## Current Features
- User registration
- User login
- Basic user listing
- Health check endpoint

## Known Issues (You will fix these)
This code has multiple security vulnerabilities you need to identify and fix:
- Hardcoded secrets
- SQL injection vulnerabilities
- Weak password hashing
- Missing input validation
- Insecure logging

## Setup Instructions

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## API Endpoints

### Health Check
```bash
GET /health
```

### Create User
```bash
POST /users
{
    "username": "john_doe",
    "password": "password123"
}
```

### Login
```bash
POST /login
{
    "username": "john_doe",
    "password": "password123"
}
```

### List Users
```bash
GET /users
```

## What To Do Next
Create a new repository you own (or use your GitHub Classroom repo with admin access) and copy this folder’s contents into it. Then:
1. Set up branch protection and a PR-based workflow
2. Add security scanning and pre-commit hooks
3. Fix all security vulnerabilities
4. Add professional documentation (README, PR template, contributing)
5. Create a CI workflow to run tests, lint, and security scans
