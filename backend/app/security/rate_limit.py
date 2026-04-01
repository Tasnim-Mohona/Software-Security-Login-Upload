from slowapi import Limiter
from slowapi.util import get_remote_address

# Industry standard algorithmic sliding window rate limiter
limiter = Limiter(key_func=get_remote_address)
