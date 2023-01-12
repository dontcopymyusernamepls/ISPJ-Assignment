import random
import string

def generate_random():
    char_string = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(char_string) for i in range(32))
    return random_string
    
    
def append_random(password, random_string):
    add_string = password + random_string
    return add_string