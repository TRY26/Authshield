from pymongo import MongoClient

MONGO_URL = "mongodb+srv://tunganirishi_db_user:vt9A3IVT19mZXODK@authshield.nnxiqoh.mongodb.net/?appName=authshield"

client = MongoClient(MONGO_URL)

db = client["auth_project"]

users_collection = db["users"]
blacklist_collection = db["blacklist"]
refresh_collection = db["refresh_tokens"]
reset_collection = db["reset_tokens"]