
import bcrypt


def encrypt_password(user_password):
    user_password = user_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(user_password, salt)
    return hashed_password


def check_hash(entered_password, hashed_password):
    entered_password = entered_password.encode('utf-8')
    return bcrypt.checkpw(entered_password, hashed_password)
