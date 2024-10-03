# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime, timedelta
from typing import List, Optional, Annotated
from jose import jwt
from passlib.context import CryptContext
import motor.motor_asyncio
from bson import ObjectId
import os

# MongoDB setup
MONGO_DETAILS = os.getenv("MONGO_DETAILS", "mongodb://localhost:27017")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DETAILS)
database = client.wallet_db

# Pydantic models
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")

class UserModel(BaseModel):
    id: Optional[Annotated[PyObjectId, Field(alias="_id")]] = None
    username: str
    hashed_password: str
    
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True, json_encoders={ObjectId: str})

class AccountModel(BaseModel):
    id: Optional[Annotated[PyObjectId, Field(alias="_id")]] = None
    user_id: PyObjectId
    balance: float = 0.0
    
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True, json_encoders={ObjectId: str})

class TransactionModel(BaseModel):
    id: Optional[Annotated[PyObjectId, Field(alias="_id")]] = None
    account_id: PyObjectId
    amount: float
    transaction_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True, json_encoders={ObjectId: str})

class UserCreate(BaseModel):
    username: str
    password: str

class UserInDB(BaseModel):
    id: str
    username: str

class Token(BaseModel):
    access_token: str
    token_type: str

class AccountBalance(BaseModel):
    balance: float

class TransactionCreate(BaseModel):
    amount: float

class TransactionResponse(BaseModel):
    id: str
    amount: float
    transaction_type: str
    timestamp: datetime

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# FastAPI app
app = FastAPI(title="Wallet Application")

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def authenticate_user(username: str, password: str):
    user = await database["users"].find_one({"username": username})
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    user = await database["users"].find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

# API endpoints
@app.post("/users", response_model=UserInDB)
async def create_user(user: UserCreate):
    db_user = await database["users"].find_one({"username": user.username})
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    new_user = await database["users"].insert_one({"username": user.username, "hashed_password": hashed_password})
    created_user = await database["users"].find_one({"_id": new_user.inserted_id})
    await database["accounts"].insert_one({"user_id": new_user.inserted_id, "balance": 0.0})
    return UserInDB(id=str(created_user["_id"]), username=created_user["username"])

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/balance", response_model=AccountBalance)
async def get_balance(current_user: dict = Depends(get_current_user)):
    account = await database["accounts"].find_one({"user_id": current_user["_id"]})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"balance": account["balance"]}

@app.post("/credit", response_model=TransactionResponse)
async def credit_account(
    transaction: TransactionCreate,
    current_user: dict = Depends(get_current_user)
):
    account = await database["accounts"].find_one({"user_id": current_user["_id"]})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    new_balance = account["balance"] + transaction.amount
    await database["accounts"].update_one(
        {"_id": account["_id"]},
        {"$set": {"balance": new_balance}}
    )
    new_transaction = await database["transactions"].insert_one({
        "account_id": account["_id"],
        "amount": transaction.amount,
        "transaction_type": "credit",
        "timestamp": datetime.utcnow()
    })
    created_transaction = await database["transactions"].find_one({"_id": new_transaction.inserted_id})
    return created_transaction

@app.post("/debit", response_model=TransactionResponse)
async def debit_account(
    transaction: TransactionCreate,
    current_user: dict = Depends(get_current_user)
):
    account = await database["accounts"].find_one({"user_id": current_user["_id"]})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    if account["balance"] < transaction.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    new_balance = account["balance"] - transaction.amount
    await database["accounts"].update_one(
        {"_id": account["_id"]},
        {"$set": {"balance": new_balance}}
    )
    new_transaction = await database["transactions"].insert_one({
        "account_id": account["_id"],
        "amount": transaction.amount,
        "transaction_type": "debit",
        "timestamp": datetime.utcnow()
    })
    created_transaction = await database["transactions"].find_one({"_id": new_transaction.inserted_id})
    return created_transaction

@app.get("/transactions", response_model=List[TransactionResponse])
async def get_transactions(current_user: dict = Depends(get_current_user)):
    account = await database["accounts"].find_one({"user_id": current_user["_id"]})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    transactions = await database["transactions"].find({"account_id": account["_id"]}).to_list(1000)
    return transactions

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)