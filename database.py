from pymongo import MongoClient
from pymongo.errors import ConfigurationError, PyMongoError
from bson import ObjectId
import config
import logging
import os
import json
import threading

logger = logging.getLogger("authshield.database")

# Local embedded persistent collection fallback
class LocalCollection:
    def __init__(self, filename):
        self.filename = filename
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    self.docs = json.load(f)
            except Exception:
                self.docs = []
        else:
            self.docs = []

    def _save(self):
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.docs, f, default=str, indent=2)
        except Exception as e:
            logger.error(f"Error saving local data: {e}")

    def _match(self, doc, query):
        for k, v in query.items():
            if k == '_id':
                if str(doc.get('_id')) != str(v):
                    return False
            elif doc.get(k) != v:
                return False
        return True

    def find_one(self, query, projection=None):
        with self.lock:
            self._load()
            for doc in self.docs:
                if self._match(doc, query):
                    res = doc.copy()
                    if projection and projection.get('hashed_password') == 0:
                        res.pop('hashed_password', None)
                    return res
            return None

    def insert_one(self, doc):
        with self.lock:
            self._load()
            new_doc = doc.copy()
            if '_id' not in new_doc:
                new_doc['_id'] = str(ObjectId())
            self.docs.append(new_doc)
            self._save()
            class InsertResult:
                def __init__(self, inserted_id):
                    self.inserted_id = inserted_id
            return InsertResult(new_doc['_id'])

    def update_one(self, query, update):
        with self.lock:
            self._load()
            matched = 0
            for doc in self.docs:
                if self._match(doc, query):
                    matched += 1
                    if '$set' in update:
                        doc.update(update['$set'])
                    if '$inc' in update:
                        for ik, iv in update['$inc'].items():
                            doc[ik] = doc.get(ik, 0) + iv
                    break
            self._save()
            class UpdateResult:
                matched_count = matched
            return UpdateResult()

    def update_many(self, query, update):
        with self.lock:
            self._load()
            for doc in self.docs:
                if self._match(doc, query):
                    if '$set' in update:
                        doc.update(update['$set'])
            self._save()

    def delete_one(self, query):
        with self.lock:
            self._load()
            for i, doc in enumerate(self.docs):
                if self._match(doc, query):
                    del self.docs[i]
                    break
            self._save()

    def delete_many(self, query):
        with self.lock:
            self._load()
            self.docs = [d for d in self.docs if not self._match(d, query)]
            self._save()

    def find(self, query=None, projection=None):
        with self.lock:
            self._load()
            results = []
            for doc in self.docs:
                if not query or self._match(doc, query):
                    res = doc.copy()
                    if projection and projection.get('hashed_password') == 0:
                        res.pop('hashed_password', None)
                    results.append(res)
            return results


client = None
db = None
users_collection = None
blacklist_collection = None
refresh_collection = None
reset_collection = None
engine_mode = "unknown"

def get_database():
    global client, db, users_collection, blacklist_collection, refresh_collection, reset_collection, engine_mode

    # Attempt real MongoDB connection
    if client is None and engine_mode != "local":
        try:
            temp_client = MongoClient(
                config.MONGO_URL,
                serverSelectionTimeoutMS=2000
            )
            # Probe connectivity
            temp_client.admin.command("ping")
            client = temp_client
            db = client[config.MONGO_DB_NAME]
            users_collection = db["users"]
            blacklist_collection = db["blacklist"]
            refresh_collection = db["refresh_tokens"]
            reset_collection = db["reset_tokens"]
            engine_mode = "mongodb"
            logger.info("Connected to live MongoDB cluster successfully.")
            return db
        except (ConfigurationError, PyMongoError, Exception) as e:
            logger.warning(f"MongoDB unavailable ({e}). Activating embedded persistent database fallback.")
            engine_mode = "local"

    # Fallback to embedded persistent engine
    if engine_mode == "local" or users_collection is None:
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        users_collection = LocalCollection(os.path.join(data_dir, "users.json"))
        blacklist_collection = LocalCollection(os.path.join(data_dir, "blacklist.json"))
        refresh_collection = LocalCollection(os.path.join(data_dir, "refresh_tokens.json"))
        reset_collection = LocalCollection(os.path.join(data_dir, "reset_tokens.json"))
        engine_mode = "local"

    return db

# Initialize on import
get_database()
