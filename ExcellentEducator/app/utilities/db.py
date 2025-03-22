from pymongo.mongo_client import MongoClient
from app.config import MONGODB_URI
import gridfs

client = MongoClient(MONGODB_URI)
db = client["ExcellentEducator"]

def get_db():
    return db

def get_gridfs():
    return gridfs.GridFS(db)