import redis


class Redis:
    def __init__(self, host='localhost', port=6379, db=0):
        self.redis = redis.Redis(host=host, port=port, db=db)

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

    def print_all(self):

        """Prints all keys and their values in the Redis database."""
        # Iterating over all the keys in the Redis database
        for key in self.redis.keys():
            print(key)
            key_type = self.redis.type(key)
            if key_type == b'string':
                print(key, ":", self.redis.get(key).decode())
            elif key_type == b'hash':
                print(key, ":", self.redis.hgetall(key))


if __name__ == "__main__":
    # Creating an instance of the Redis class
    r = Redis()

    # Setting an empty dictionary as the value of the key 'example'
    r.hset_dict("example")

    # retrieving the values of the key
    print(r.hgetall("example"))

    self.redis_virus.hset_dict(str(md5("virus.exe")),
                               {"num_of_rules": 0, "num_of_packers": 0, "fractioned_imports_test": 0,
                                "rick_optional_linker_test": 0, "imports_test": 0, "num_of_!": 0,
                                "num_of_identifies": 0, "num_of_has_passed_cpu": 0, "num_of_engines:": 0,
                                "num_of_fuzzy_found": 0, "final_assesment": 0})
    # self.redis_virus.print_all()

    # Output: {}