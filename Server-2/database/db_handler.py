import json
import os
import pymysql, random
import psutil
import logging
import re
from dbutils.pooled_db import PooledDB

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

class DatabaseManager:
    def __init__(self, config_path=None, db_section='1_DB'):
        self.config_path = config_path or os.getenv('DB_CONFIG_PATH', 'database/mysql.json')
        self.db_section = db_section
        self.pool = None
        self.ssl_config = None

    def _load_db_config(self):
        try:
            with open(self.config_path, 'r') as f:
                db_config = json.load(f).get(self.db_section, {})
                if not db_config:
                    raise ValueError(f"No configuration found for section '{self.db_section}' in '{self.config_path}'.")
                return db_config
        except FileNotFoundError:
            error_message = f"Database configuration file '{self.config_path}' not found."
            logging.error(error_message)
            raise Exception(error_message)
        except json.JSONDecodeError as e:
            error_message = f"Error decoding JSON from the configuration file '{self.config_path}': {e}."
            logging.error(error_message)
            raise Exception(error_message)
        except Exception as e:
            error_message = f"An unexpected error occurred while loading the database configuration: {e}."
            logging.error(error_message)
            raise Exception(error_message)

    def _validate_db_config(self, db_config):
        """Validate database configuration parameters."""
        required_fields = ['host', 'user', 'password', 'database', 'port']
        for field in required_fields:
            if field not in db_config:
                raise ValueError(f"Missing required database configuration field: '{field}'.")
        if not re.match(r'^[a-zA-Z0-9.-]+$', db_config['host']):
            raise ValueError(f"Invalid host name: '{db_config['host']}'. Must be a valid hostname or IP.")
        if not isinstance(db_config['port'], int) or not (1 <= db_config['port'] <= 65535):
            raise ValueError(f"Invalid port number: '{db_config['port']}'. Must be an integer between 1 and 65535.")
        for field in ['user', 'database']:
            if not re.match(r'^\w+$', db_config[field]):
                raise ValueError(f"Invalid {field} name: '{db_config[field]}'. Must be alphanumeric with underscores.")

    def _calculate_pool_parameters(self):
        total_memory = psutil.virtual_memory().total
        num_cpus = psutil.cpu_count()
        max_connections = min(20, num_cpus * 2)
        min_cached = max(1, max_connections // 2)
        max_cached = max_connections
        max_shared = max_connections
        return max_connections, min_cached, max_cached, max_shared

    def _initialize_pool(self):
        try:
            db_config = self._load_db_config()
            self._validate_db_config(db_config) 
            self._create_database_if_not_exists(db_config)  # Ensure database exists
            self.max_connections, self.min_cached, self.max_cached, self.max_shared = self._calculate_pool_parameters()
            self.pool = PooledDB(
                creator=pymysql,
                maxconnections=self.max_connections,
                mincached=self.min_cached,
                maxcached=self.max_cached,
                maxshared=self.max_shared,
                blocking=True,
                host=db_config['host'],
                user=db_config['user'],
                password=db_config['password'],
                database=db_config['database'],
                port=int(db_config['port']),
                cursorclass=pymysql.cursors.DictCursor
            )
        except ValueError as ve:
            error_message = f"Configuration error: {ve}."
            logging.error(error_message)
            raise Exception(error_message)
        except Exception as e:
            error_message = f"Failed to initialize the database connection pool: {e}."
            logging.error(error_message)
            raise Exception(error_message)

    def _create_database_if_not_exists(self, db_config):
        """Check if the database exists, and create it if not."""
        try:
            # Connect to MySQL server (not to the database)
            connection = pymysql.connect(
                host=db_config['host'],
                user=db_config['user'],
                password=db_config['password'],
                port=int(db_config['port']),
                cursorclass=pymysql.cursors.DictCursor
            )
            with connection.cursor() as cursor:
                # Check if the database exists
                cursor.execute("SHOW DATABASES LIKE %s", (db_config['database'],))
                result = cursor.fetchone()
                if not result:
                    # Database doesn't exist, create it
                    cursor.execute(f"CREATE DATABASE {db_config['database']}")
                    logging.info(f"Database '{db_config['database']}' created.")
            connection.close()
        except Exception as e:
            error_message = f"Failed to check or create the database: {e}."
            logging.error(error_message)
            raise Exception(error_message)

    def get_connection(self):
        if self.pool is None:
            logging.info("Initializing connection pool (lazy loading)...")
            self._initialize_pool()
        try:
            return self.pool.connection()
        except Exception as e:
            error_message = f"Failed to get a connection from the pool: {e}."
            logging.error(error_message)
            raise Exception(error_message)

    def close_pool(self):
        if self.pool:
            self.pool.close()
            self.pool = None

# Instantiate a global DatabaseManager object to reuse across the app
db_manager = DatabaseManager()



def test_database_manager():
    try:
        logging.info("Initializing DatabaseManager...")
        db_manager._initialize_pool()
        logging.info("Getting a database connection...")
        connection = db_manager.get_connection()
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS test_table (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))")
            names = ["Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Hank", "Ivy", "Jack"]
            for name in random.sample(names, 10):
                cursor.execute("INSERT INTO test_table (name) VALUES (%s)", (name,))
            connection.commit()
            logging.info("10 random values inserted successfully.")
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM test_table")
            result = cursor.fetchall()
            logging.info(f"Retrieved data: {result}")
        connection.close()
        logging.info("Test completed successfully.")
    except Exception as e:
        logging.error(f"Test failed: {e}")
    finally:
        db_manager.close_pool()
        logging.info("Database connection pool closed.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_database_manager()
