from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

client = AsyncIOMotorClient(settings.MONGO_DETAILS)
database = client.yondatax_db

async def get_database():
    return database