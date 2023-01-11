import redis

# Connect to a Redis server running on localhost
r = redis.Redis(host='localhost', port=6379, db=0)

# Set a value
r.set('mykey', 'myvalue')

# Get a value
value = r.get('mykey')
print(value)