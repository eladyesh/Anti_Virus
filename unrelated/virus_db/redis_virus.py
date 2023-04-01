import redis
import pickle
from flask import Flask, jsonify
from flask_redis import FlaskRedis


class Redis:
    def __init__(self, host='localhost', port=6379, db=0):
        self.redis = redis.Redis(host=host, port=port, db=db)
        self.app = Flask(__name__)
        self.app.config['REDIS_URL'] = f'redis://{host}:{port}/{db}'
        self.redis_client = FlaskRedis(self.app)

        @self.app.route('/redis_data')
        def show_all():
            """Show all the contents of the Redis database using Flask-Redis."""
            all_keys = self.redis_client.keys()
            result = {}
            for key in all_keys:
                key_type = self.redis_client.type(key)
                if key_type == 'string':
                    result[key] = self.redis_client.get(key)
                elif key_type == 'hash':
                    result[key] = self.redis_client.hgetall(key)
            return jsonify(result)

    def run(self, debug=False):
        """Run the Flask app."""
        self.app.run(debug=debug)

    def set(self, key, value):
        """Set a key-value pair in the Redis database."""
        self.redis.set(key, value)

    def hset_dict(self, key, d=None):
        """Set a key-value pair where key is a string and value is a dictionary"""
        if d is None:
            d = {}
        for k, v in d.items():
            self.redis.hset(key, k, v)

    def hgetall(self, key):
        """Retrieve all the fields and values of a hash stored at key"""
        return self.redis.hgetall(key)

    def get(self, key):
        """Retrieve the value of a key from the Redis database."""
        return self.redis.get(key)

    def delete(self, key):
        """Delete a key from the Redis database."""
        self.redis.delete(key)

    def incr(self, key):
        """Increment the value of a key in the Redis database."""
        self.redis.incr(key)

    def decr(self, key):
        """Decrement the value of a key in the Redis database."""
        self.redis.decr(key)

    def keys(self):
        """Retrieve all keys in the Redis database."""
        return self.redis.keys()

    def flush(self):
        """Deletes all existing keys in the Redis database."""
        self.redis.flushall()

    def delete_keys_without_hash(self):
        for key in self.redis.keys():
            if self.redis.type(key) == b"string":
                if len(key) < 32:
                    self.delete(key)
            else:
                self.delete(key)

    def exists(self, key):
        return self.redis.exists(key)

    def print_key(self, key, k, pick):
        if pick:
            print(pickle.loads(self.redis.hgetall(key)[k.encode()]))
        else:
            print(self.redis.hgetall(key)[k.encode()])

    def get_key(self, key, k, pick):
        if pick:
            return pickle.loads(self.redis.hgetall(key)[k.encode()])
        else:
            return self.redis.hgetall(key)[k.encode()]

    def get_key_type(self, key, k, pick):
        if pick:
            return type(pickle.loads(self.redis.hgetall(key)[k.encode()]))
        else:
            return type(self.redis.hgetall(key)[k.encode()])

    def hset(self, key, k, v):
        self.redis.hset(key, k, v)

    def print_all(self):

        """Prints all keys and their values in the Redis database."""
        # Iterating over all the keys in the Redis database
        print("printing all")
        for key in self.redis.keys():
            print(key)
            key_type = self.redis.type(key)
            if key_type == b'string':
                print(key, ":", self.redis.get(key).decode())
            elif key_type == b'hash':
                print(key, ":", self.redis.hgetall(key))

    def change_to_reg(self):
        for hash_key in self.redis.keys():
            if self.redis.type(hash_key) == b'hash':
                cursor = '0'
                while cursor != 0:
                    cursor, data = self.redis.hscan(hash_key, cursor=cursor)
                    for key, value in data.items():
                        if isinstance(key, bytes):
                            key_decoded = key.decode()
                        if isinstance(value, bytes):
                            value_decoded = value.decode()
                        self.redis.hdel(hash_key, key)
                        self.redis.hset(hash_key, key_decoded, value_decoded)
            if isinstance(hash_key, bytes):
                hash_key_decoded = hash_key.decode()


if __name__ == "__main__":
    # Creating an instance of the Redis class
    r = Redis()
    r.flush()
    pass
