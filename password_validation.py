import re

def validate_password(password):
    if not re.search(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}', password):
        error = "The password does not meet the requirements :\n"
        if len(password) < 8:
            error += "- Length  must be 8+!\n"
        if not re.search(r'[a-z]', password) or not re.search(r'[A-Z]', password):
            error += "- Must contain upper and lower case!\n"
        if not re.search(r'\d', password):
            error += "- Must contain digits!\n"
        if not re.search(r'[^a-zA-Z0-9]', password):
            error += "- Must contain a sign!\n"
        return error
    return False
