import redis
import pickle
from flask import Flask, jsonify
from flask_redis import FlaskRedis


class Redis:
    def __init__(self, host='localhost', port=6379, db=0):
        """
        Initialize the Redis class with the specified host, port, and database.

        Parameters:
        - host (str): Redis server host address. Default is 'localhost'.
        - port (int): Redis server port number. Default is 6379.
        - db (int): Redis database index. Default is 0.
        """
        self.redis = redis.Redis(host=host, port=port, db=db)
        self.app = Flask(__name__)
        self.app.config['REDIS_URL'] = f'redis://{host}:{port}/{db}'
        self.redis_client = FlaskRedis(self.app)

        @self.app.route('/redis_data')
        def show_all():
            """
            Show all the contents of the Redis database using Flask-Redis.

            Returns:
            - flask.Response: JSON response containing all the Redis database contents.
            """
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
        """
        Run the Flask app.

        Parameters:
        - debug (bool): Run the Flask app in debug mode. Default is False.
        """
        self.app.run(debug=debug)

    def set(self, key, value):
        """
        Set a key-value pair in the Redis database.

        Parameters:
        - key (str): Key to be set.
        - value: Value to be associated with the key.
        """
        self.redis.set(key, value)

    def hset_dict(self, key, d=None):
        """
        Set a key-value pair where the key is a string and the value is a dictionary.

        Parameters:
        - key (str): Key to be set.
        - d (dict): Dictionary value to be associated with the key. Default is an empty dictionary.
        """
        if d is None:
            d = {}
        for k, v in d.items():
            self.redis.hset(key, k, v)

    def hgetall(self, key):
        """
        Retrieve all the fields and values of a hash stored at the specified key.

        Parameters:
        - key (str): Key of the hash to retrieve.

        Returns:
        - dict: Dictionary containing all the fields and values of the hash.
        """
        return self.redis.hgetall(key)

    def get(self, key):
        """
        Retrieve the value of a key from the Redis database.

        Parameters:
        - key (str): Key to retrieve the value for.

        Returns:
        - str: Value associated with the key.
        """
        return self.redis.get(key)

    def delete(self, key):
        """
        Delete a key from the Redis database.

        Parameters:
        - key (str): Key to delete from the database.
        """
        self.redis.delete(key)

    def incr(self, key):
        """
        Increment the value of a key in the Redis database.

        Parameters:
        - key (str): Key to increment the value of.
        """
        self.redis.incr(key)

    def decr(self, key):
        """
        Decrement the value of a key in the Redis database.

        Parameters:
        - key (str): Key to decrement the value of.
        """
        self.redis.decr(key)

    def keys(self):
        """
        Retrieve all keys in the Redis database.

        Returns:
        - list: List of all keys in the Redis database.
        """
        return self.redis.keys()

    def flush(self):
        """
        Deletes all existing keys in the Redis database.
        """
        self.redis.flushall()

    def delete_keys_without_hash(self):
        """
        Delete keys from the Redis database that are not of type 'hash'.
        Keys of type 'string' with a length less than 32 will also be deleted.
        """
        for key in self.redis.keys():
            if self.redis.type(key) == b"string":
                if len(key) < 32:
                    self.delete(key)
            else:
                self.delete(key)

    def exists(self, key):
        """
        Check if a key exists in the Redis database.

        Parameters:
        - key (str): Key to check for existence.

        Returns:
        - bool: True if the key exists, False otherwise.
        """
        return self.redis.exists(key)

    def print_key(self, key, k, pick):
        """
        Print the value of a specific field in a hash stored at a key.

        Parameters:
        - key (str): Key of the hash.
        - k (str): Field to retrieve the value for.
        - pick (bool): Whether the value is pickled and needs to be unpickled before printing.
        """
        if pick:
            print(pickle.loads(self.redis.hgetall(key)[k.encode()]))
        else:
            print(self.redis.hgetall(key)[k.encode()])

    def get_key(self, key, k, pick):
        """
        Retrieve the type of the value of a specific field in a hash stored at a key.

        Parameters:
        - key (str): Key of the hash.
        - k (str): Field to retrieve the type for.
        - pick (bool): Whether the value is pickled and needs to be unpickled before checking its type.

        Returns:
        - type: Type of the value associated with the field.
        """
        if pick:
            return pickle.loads(self.redis.hgetall(key)[k.encode()])
        else:
            return self.redis.hgetall(key)[k.encode()]

    def get_key_type(self, key, k, pick):
        """
        Retrieve the type of the value of a specific field in a hash stored at a key.

        Parameters:
        - key (str): Key of the hash.
        - k (str): Field to retrieve the type for.
        - pick (bool): Whether the value is pickled and needs to be unpickled before checking its type.

        Returns:
        - type: Type of the value associated with the field.
        """
        if pick:
            return type(pickle.loads(self.redis.hgetall(key)[k.encode()]))
        else:
            return type(self.redis.hgetall(key)[k.encode()])

    def hset(self, key, k, v):
        """
        Set the value of a specific field in a hash stored at a key.

        Parameters:
        - key (str): Key of the hash.
        - k (str): Field to set the value for.
        - v: Value to be associated with the field.
        """
        self.redis.hset(key, k, v)

    def print_all(self):
        """
        Prints all keys and their values in the Redis database.
        """

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
        """
        Converts all hash keys and values from bytes to regular strings.
        """
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
