
#! form validation for username,email,password 
import re


def validation_username(username):
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return {'response': 'Invalid username format. Only alphanumeric characters and underscore (_) are allowed.'}
    return None


def validation_email(email):
    email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', re.IGNORECASE)
    if not email_regex.match(email):
        return {'response': 'invalid gmail format. backend'}
    return None


def validation_password(password):
    if len(password) < 8:
        return {'response': 'Password must be at least 8 characters long. backend'}
    
    if not re.search(r'[A-Z]', password):
        return {'response': 'Password must contain at least one uppercase letter. backend'}
    
    if not re.search(r'\d', password):
        return {'response': 'Password must contain at least one number. backend'}
    
    if not re.search(r'[!@#$%^&*]', password):
        return {'response': 'Password must contain at least one special character. backend'}
    
    return None
        