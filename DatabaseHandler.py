import os
from pymongo import MongoClient
from dotenv import load_dotenv

class DatabaseHandler:
    def __init__(self):
        # Load environment variables from a .env file (optional but recommended)
        load_dotenv()

        # Get MongoDB URI from environment variable
        mongo_uri = os.getenv("MONGO_URI")

        if not mongo_uri:
            raise ValueError("MongoDB URI is not set. Please configure the environment variable 'MONGO_URI'.")

        self.client = MongoClient(mongo_uri)
        self.db = self.client["password_manager"]
        self.users_collection = self.db["users"]

    def load_user(self, username):
        return self.users_collection.find_one({"username": username})

    def save_user(self, username, master_password_hash, passwords):
        self.users_collection.update_one(
            {"username": username},
            {"$set": {"master_password_hash": master_password_hash, "passwords": passwords}},
            upsert=True
        )

    def update_passwords(self, username, passwords):
        self.users_collection.update_one(
            {"username": username},
            {"$set": {"passwords": passwords}}
        )
