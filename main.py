import os
import redis
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import Enum
from typing import Annotated, List, Optional, Union

import httpx
import motor.motor_asyncio
from bson import ObjectId
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.openapi.utils import get_openapi
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field, GetJsonSchemaHandler
from pydantic_core import core_schema

# MongoDB setup
MONGO_DETAILS = os.getenv("MONGO_DETAILS", "mongodb://localhost:27017")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DETAILS)
database = client.yondatax_db


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, info):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        return core_schema.with_info_after_validator_function(
            cls.validate,
            core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(str),
        )

    @classmethod
    def __get_pydantic_json_schema__(cls, _schema, handler: GetJsonSchemaHandler):
        return handler(core_schema.str_schema())
    
# Redis setup
redis_client = redis.Redis(host='localhost', port=6379, db=0)


# Models
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"


class UserModel(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str
    hashed_password: str
    role: str = UserRole.USER  # Default role is 'user'

    class Config:
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = (True,)
        populate_by_name = True


class AccountModel(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    user_id: PyObjectId
    wallets: List[PyObjectId] = []

    class Config:
        json_encoders = {ObjectId: str}
        populate_by_name = True


class TransactionModel(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    account_id: PyObjectId
    amount: float
    transaction_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = (True,)
        populate_by_name = True


class Currency(str, Enum):
    USD = "USD"
    ZAR = "ZAR"
    EUR = "EUR"
    GBP = "GBP"


class UserCreate(BaseModel):
    username: str
    password: str
    default_currency: Currency = Currency.ZAR
    role: UserRole = UserRole.USER  # Default to regular user unless specified


class UserInDB(BaseModel):
    id: str
    username: str


class Token(BaseModel):
    access_token: str
    token_type: str


class AccountBalance(BaseModel):
    balance: float


class TransactionType(str, Enum):
    CREDIT = "credit"
    DEBIT = "debit"
    TRANSFER = "transfer"


class TransactionCreate(BaseModel):
    amount: float


class TransactionCredit(BaseModel):
    user_id: str
    amount: float


class TransactionDebit(BaseModel):
    user_id: str
    amount: float


class TransactionResponse(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    wallet_id: PyObjectId
    amount: float
    transaction_type: TransactionType
    timestamp: datetime

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        populate_by_name = True
        from_attributes = True


class WalletCreate(BaseModel):
    currency: Currency


class WalletResponse(BaseModel):
    id: str
    currency: Currency
    balance: float


class WalletUpdate(BaseModel):
    name: Optional[str] = None


class TransferRequest(BaseModel):
    source_wallet_id: str
    target_wallet_id: str
    amount: float = Field(gt=0)


# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "jti": str(uuid.uuid4()),  # Generate a unique identifier
        "exp": expire
    })
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
        # Extract JTI
        jti = payload.get("jti")
        if jti is None:
            raise HTTPException(status_code=401, detail="Token has no JTI")

        # Check if the token's JTI is blacklisted in Redis
        if redis_client.get(f"blacklist:{jti}") is not None:
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception

    user = await database["users"].find_one({"username": username})
    if user is None:
        raise credentials_exception
    elif user["role"] == UserRole.ADMIN.value:
        return user

    # Ensure the user has an account and at least one wallet
    account = await get_user_account(user["_id"])
    if not account["wallets"]:
        # If no wallets exist, create a default one with ZAR as the currency
        default_wallet = await database["wallets"].insert_one(
            {
                "user_id": user["_id"],
                "currency": Currency.ZAR,
                "balance": 0.0,
                "created_at": datetime.utcnow(),
            }
        )
        await database["accounts"].update_one(
            {"_id": account["_id"]}, {"$push": {"wallets": default_wallet.inserted_id}}
        )

    return user


# Helper function to conditionally fetch current user
async def get_current_user_if_needed(
    request: Request, authorization: str = Header(None)
) -> Optional[dict]:
    if authorization:
        return await get_current_user(authorization)
    return None


async def get_user_account(user_id: ObjectId):
    account = await database["accounts"].find_one({"user_id": user_id})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return account


async def get_exchange_rate(from_currency: str, to_currency: str) -> float:
    api_key = "cd11219ba9bf8874e7acc599"
    url = f"https://v6.exchangerate-api.com/v6/{api_key}/latest/{from_currency}"

    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        data = response.json()

        if data["result"] == "success":
            conversion_rates = data["conversion_rates"]
            if to_currency in conversion_rates:
                return conversion_rates[to_currency]
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Currency {to_currency} not found in conversion rates",
                )
        else:
            raise HTTPException(
                status_code=400, detail="Failed to fetch exchange rates"
            )


async def is_admin_user(current_user: dict):
    if current_user["role"] != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action",
        )


async def get_wallet(wallet_id: str, user_id: ObjectId):
    wallet = await database["wallets"].find_one(
        {"_id": ObjectId(wallet_id), "user_id": user_id}
    )
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return wallet


async def update_wallet_balance(wallet_id: ObjectId, amount: float):
    result = await database["wallets"].update_one(
        {"_id": wallet_id}, {"$inc": {"balance": amount}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update wallet balance")


async def create_transaction(
    wallet_id: ObjectId, amount: float, transaction_type: TransactionType
):
    transaction = {
        "wallet_id": wallet_id,
        "amount": amount,
        "transaction_type": transaction_type,
        "timestamp": datetime.utcnow(),
    }
    result = await database["transactions"].insert_one(transaction)
    return result.inserted_id


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create admin user if no users exist
    user_count = await database["users"].count_documents({})

    if user_count == 0:
        admin_username = "testadmin"
        admin_password = "adminpassword"
        hashed_password = get_password_hash(admin_password)

        # Insert the admin user into the users collection
        await database["users"].insert_one(
            {
                "username": admin_username,
                "hashed_password": hashed_password,
                "role": UserRole.ADMIN.value,  # Admin role
                "created_at": datetime.utcnow(),
            }
        )
        print(
            f"Admin user created with username: {admin_username} and password: {admin_password}"
        )

    # Yield control back to FastAPI (app lifecycle continues)
    yield


# FastAPI app
app = FastAPI(lifespan=lifespan)


@app.get("/items/{item_id}")
async def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}


# Customize OpenAPI schema to show up in Swagger UI
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="YondaTax API",
        version="1.0.0",
        description="API for managing digital wallets and transactions",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


# Assign the custom OpenAPI schema to the app
app.openapi = custom_openapi

# API endpoints


@app.get("/currencies", response_model=List[Currency])
async def list_currencies():
    """
    Retrieve a list of supported currencies.

    Returns:
    - **List[Currency]**: A list of supported currency codes.
    """
    return list(Currency)


@app.post("/users", response_model=UserInDB)
async def create_user(
    user: UserCreate,
    current_user: Optional[dict] = Depends(
        get_current_user_if_needed
    ),  # Fetch user only if needed
):
    """
    Create a new user.

    - **user**: The user details to create.
    - **current_user**: The authenticated user (if provided). Only required for admin operations.

    Returns:
    - **UserInDB**: The created user's details.

    Raises:
    - **400 Bad Request**: If the username is already registered.
    - **403 Forbidden**: If trying to create an admin user without admin privileges.
    """
    db_user = await database["users"].find_one({"username": user.username})
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Conditionally check for admin role creation
    if user.role == UserRole.ADMIN:
        if current_user is None or current_user["role"] != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=403, detail="Only admins can create other admins"
            )

    hashed_password = get_password_hash(user.password)

    # Create user
    new_user = await database["users"].insert_one(
        {
            "username": user.username,
            "hashed_password": hashed_password,
            "role": user.role.value,  # Store the enum value in the database
            "created_at": datetime.utcnow(),
        }
    )

    # Create account for the user
    new_account = await database["accounts"].insert_one(
        {"user_id": new_user.inserted_id, "wallets": []}
    )

    # Create a default wallet for the user
    default_wallet = await database["wallets"].insert_one(
        {
            "user_id": new_user.inserted_id,
            "currency": user.default_currency,
            "balance": 0.0,
            "created_at": datetime.utcnow(),
        }
    )

    # Update the account with the new wallet
    await database["accounts"].update_one(
        {"_id": new_account.inserted_id},
        {"$push": {"wallets": default_wallet.inserted_id}},
    )

    created_user = await database["users"].find_one({"_id": new_user.inserted_id})
    return UserInDB(id=str(created_user["_id"]), username=created_user["username"])


@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate a user and return an access token.

    - **form_data**: The username and password for authentication.

    Returns:
    - **Token**: An access token for the authenticated user.

    Raises:
    - **401 Unauthorized**: If the username or password is incorrect.
    """
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


@app.post("/logout")
async def logout(authorization: str = Header(None)):
    """
    Logout the current user by invalidating their access token.
    
    Args:
        authorization (str): The authorization header containing the access token.
    
    Returns:
        dict: A message indicating the user has been successfully logged out.
    
    Raises:
        HTTPException: If the provided access token is invalid or missing.
    """
    if authorization is None:
        raise HTTPException(status_code=400, detail="Authorization header is missing")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Authorization header must start with 'Bearer '")
    
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Check if 'jti' exists in the token payload
        if 'jti' not in payload:
            raise HTTPException(status_code=400, detail="Token is missing 'jti'")
        
        jti = payload["jti"]
        exp = payload["exp"]
        
        # Blacklist the token until its expiration
        redis_client.setex(f"blacklist:{jti}", exp - int(time.time()), "true")
        return {"message": "Successfully logged out"}
    
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    except IndexError:
        raise HTTPException(status_code=400, detail="Authorization token is malformed")



@app.post("/wallets", response_model=WalletResponse)
async def create_wallet(
    wallet: WalletCreate, current_user: dict = Depends(get_current_user)
):
    """
    Create a new wallet for the authenticated user.

    - **wallet**: The wallet details to create
    - **current_user**: The authenticated user (automatically injected)

    Returns:
    - **WalletResponse**: The created wallet details

    Raises:
    - **400 Bad Request**: If a wallet with the specified currency already exists
    - **401 Unauthorized**: If the user is not authenticated
    """
    # Check if the user already has a wallet with the specified currency
    existing_wallet = await database["wallets"].find_one(
        {"user_id": current_user["_id"], "currency": wallet.currency}
    )

    if existing_wallet:
        raise HTTPException(
            status_code=400,
            detail=f"Wallet with currency {wallet.currency} already exists",
        )

    new_wallet = {
        "user_id": current_user["_id"],
        "currency": wallet.currency,
        "balance": 0.0,
        "created_at": datetime.utcnow(),
    }
    result = await database["wallets"].insert_one(new_wallet)
    created_wallet = await database["wallets"].find_one({"_id": result.inserted_id})

    # Update the user's account with the new wallet
    await database["accounts"].update_one(
        {"user_id": current_user["_id"]}, {"$push": {"wallets": result.inserted_id}}
    )

    return WalletResponse(
        id=str(created_wallet["_id"]),
        currency=created_wallet["currency"],
        balance=created_wallet["balance"],
    )


@app.get("/wallets", response_model=List[WalletResponse])
async def get_wallets(current_user: dict = Depends(get_current_user)):
    """
    Retrieve all wallets for the authenticated user.

    - **current_user**: The authenticated user (automatically injected).

    Returns:
    - **List[WalletResponse]**: A list of wallet details for the user.
    """
    user_wallets = (
        await database["wallets"].find({"user_id": current_user["_id"]}).to_list(None)
    )
    return [
        WalletResponse(
            id=str(wallet["_id"]),
            currency=wallet["currency"],
            balance=wallet["balance"],
        )
        for wallet in user_wallets
    ]


@app.put("/wallets/{wallet_id}", response_model=WalletResponse)
async def update_wallet(
    wallet_id: str,
    wallet_update: WalletUpdate,
    current_user: dict = Depends(get_current_user),
):
    """
    Update a specific wallet for the authenticated user.

    - **wallet_id**: The ID of the wallet to update.
    - **wallet_update**: The wallet details to update.
    - **current_user**: The authenticated user (automatically injected).

    Returns:
    - **WalletResponse**: The updated wallet details.

    Raises:
    - **400 Bad Request**: If the wallet update fails.
    - **404 Not Found**: If the wallet is not found.
    """
    wallet = await get_wallet(wallet_id, current_user["_id"])

    update_data = wallet_update.dict(exclude_unset=True)
    if update_data:
        result = await database["wallets"].update_one(
            {"_id": ObjectId(wallet_id)}, {"$set": update_data}
        )
        if result.modified_count == 0:
            raise HTTPException(status_code=400, detail="Wallet update failed")

    updated_wallet = await database["wallets"].find_one({"_id": ObjectId(wallet_id)})
    return WalletResponse(**updated_wallet)


@app.post("/wallets/{wallet_id}/credit", response_model=TransactionResponse)
async def credit_wallet(
    wallet_id: str,
    transaction: TransactionCredit,
    current_user: dict = Depends(get_current_user),
):
    """
    Credit (add funds to) a specific wallet. Only accessible by admin users.

    - **wallet_id**: The ID of the wallet to credit.
    - **transaction**: The credit transaction details.
    - **current_user**: The authenticated admin user (automatically injected).

    Returns:
    - **TransactionResponse**: The details of the credit transaction.

    Raises:
    - **400 Bad Request**: If the wallet balance update fails.
    - **403 Forbidden**: If the user is not an admin.
    - **404 Not Found**: If the wallet is not found.
    """
    await is_admin_user(current_user)  # Ensure the user is an admin
    wallet = await get_wallet(wallet_id, ObjectId(transaction.user_id))

    # Update wallet balance
    new_balance = wallet["balance"] + transaction.amount
    result = await database["wallets"].update_one(
        {"_id": ObjectId(wallet_id)}, {"$set": {"balance": new_balance}}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update wallet balance")

    # Create transaction record
    transaction_record = {
        "wallet_id": ObjectId(wallet_id),
        "amount": transaction.amount,
        "transaction_type": TransactionType.CREDIT,
        "timestamp": datetime.utcnow(),
    }
    new_transaction = await database["transactions"].insert_one(transaction_record)

    created_transaction = await database["transactions"].find_one(
        {"_id": new_transaction.inserted_id}
    )
    return TransactionResponse(
        id=str(created_transaction["_id"]),
        wallet_id=str(created_transaction["wallet_id"]),
        amount=created_transaction["amount"],
        transaction_type=created_transaction["transaction_type"],
        timestamp=created_transaction["timestamp"],
    )


@app.post("/wallets/{wallet_id}/debit", response_model=TransactionResponse)
async def debit_wallet(
    wallet_id: str,
    transaction: TransactionDebit,
    current_user: dict = Depends(get_current_user),
):
    """
    Debit (remove funds from) a specific wallet. Only accessible by admin users.

    - **wallet_id**: The ID of the wallet to debit.
    - **transaction**: The debit transaction details.
    - **current_user**: The authenticated admin user (automatically injected).

    Returns:
    - **TransactionResponse**: The details of the debit transaction.

    Raises:
    - **400 Bad Request**: If there are insufficient funds or the wallet balance update fails.
    - **403 Forbidden**: If the user is not an admin.
    - **404 Not Found**: If the wallet is not found.
    """
    await is_admin_user(current_user)  # Ensure the user is an admin
    wallet = await get_wallet(wallet_id, ObjectId(transaction.user_id))

    if wallet["balance"] < transaction.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # Update wallet balance
    new_balance = wallet["balance"] - transaction.amount
    result = await database["wallets"].update_one(
        {"_id": ObjectId(wallet_id)}, {"$set": {"balance": new_balance}}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update wallet balance")

    # Create transaction record
    transaction_record = {
        "wallet_id": ObjectId(wallet_id),
        "amount": transaction.amount,
        "transaction_type": TransactionType.DEBIT,
        "timestamp": datetime.utcnow(),
    }
    new_transaction = await database["transactions"].insert_one(transaction_record)

    created_transaction = await database["transactions"].find_one(
        {"_id": new_transaction.inserted_id}
    )
    return TransactionResponse(
        id=str(created_transaction["_id"]),
        wallet_id=str(created_transaction["wallet_id"]),
        amount=created_transaction["amount"],
        transaction_type=created_transaction["transaction_type"],
        timestamp=created_transaction["timestamp"],
    )


@app.post("/wallets/{wallet_id}/transfer", response_model=TransactionResponse)
async def transfer_between_wallets(
    transfer: TransferRequest, current_user: dict = Depends(get_current_user)
):
    """
    Transfer funds between two wallets owned by the authenticated user.

    - **transfer**: The transfer details, including source and target wallet IDs and amount.
    - **current_user**: The authenticated user (automatically injected).

    Returns:
    - **TransactionResponse**: The details of the transfer transaction.

    Raises:
    - **400 Bad Request**: If there are insufficient funds in the source wallet.
    - **404 Not Found**: If either the source or target wallet is not found.
    """
    source_wallet = await get_wallet(transfer.source_wallet_id, current_user["_id"])
    target_wallet = await get_wallet(transfer.target_wallet_id, current_user["_id"])

    if source_wallet["balance"] < transfer.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # Get exchange rate
    exchange_rate = await get_exchange_rate(
        source_wallet["currency"], target_wallet["currency"]
    )

    # Perform transfer
    await update_wallet_balance(ObjectId(transfer.source_wallet_id), -transfer.amount)
    await update_wallet_balance(
        ObjectId(transfer.target_wallet_id), transfer.amount * exchange_rate
    )

    # Create transactions
    source_transaction_id = await create_transaction(
        ObjectId(transfer.source_wallet_id), -transfer.amount, TransactionType.TRANSFER
    )
    target_transaction_id = await create_transaction(
        ObjectId(transfer.target_wallet_id),
        transfer.amount * exchange_rate,
        TransactionType.TRANSFER,
    )

    # Link transactions
    await database["transactions"].update_many(
        {"_id": {"$in": [source_transaction_id, target_transaction_id]}},
        {
            "$set": {
                "related_transaction_id": {
                    "$cond": [
                        {"$eq": ["$_id", source_transaction_id]},
                        target_transaction_id,
                        source_transaction_id,
                    ]
                }
            }
        },
    )

    source_transaction = await database["transactions"].find_one(
        {"_id": source_transaction_id}
    )

    return TransactionResponse(
        id=str(source_transaction["_id"]),
        wallet_id=str(source_transaction["wallet_id"]),
        amount=source_transaction["amount"],
        transaction_type=source_transaction["transaction_type"],
        timestamp=source_transaction["timestamp"],
    )


@app.get("/wallets/{wallet_id}/balance", response_model=AccountBalance)
async def get_wallet_balance(
    wallet_id: str, current_user: dict = Depends(get_current_user)
):
    """
    Retrieve the current balance of a specific wallet.

    - **wallet_id**: The ID of the wallet to check.
    - **current_user**: The authenticated user (automatically injected).

    Returns:
    - **AccountBalance**: The current balance of the wallet.

    Raises:
    - **404 Not Found**: If the wallet is not found.
    """
    wallet = await get_wallet(wallet_id, current_user["_id"])
    return AccountBalance(balance=wallet["balance"])


@app.get("/wallets/{wallet_id}/transactions", response_model=List[TransactionResponse])
async def get_wallet_transactions(
    wallet_id: str,
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve a list of transactions for a specific wallet.

    - **wallet_id**: The ID of the wallet to get transactions for.
    - **skip**: The number of transactions to skip (for pagination).
    - **limit**: The maximum number of transactions to return (for pagination).
    - **current_user**: The authenticated user (automatically injected).

    Returns:
    - **List[TransactionResponse]**: A list of transaction details for the wallet.

    Raises:
    - **404 Not Found**: If the wallet is not found.
    """
    wallet = await get_wallet(wallet_id, current_user["_id"])

    transactions = (
        await database["transactions"]
        .find({"wallet_id": ObjectId(wallet_id)})
        .sort("timestamp", -1)
        .skip(skip)
        .limit(limit)
        .to_list(None)
    )

    return [
        TransactionResponse(
            id=str(t["_id"]),
            wallet_id=str(t["wallet_id"]),
            amount=t["amount"],
            transaction_type=t["transaction_type"],
            timestamp=t["timestamp"],
        )
        for t in transactions
    ]


@app.get("/user/summary", response_model=dict)
async def get_user_summary(current_user: dict = Depends(get_current_user)):
    """
    Retrieve a summary of the authenticated user's account, including total balance,
    wallet count, and recent transactions.

    - **current_user**: The authenticated user (automatically injected).

    Returns:
    - **dict**: A dictionary containing:
        - total_balance: The sum of balances across all user's wallets.
        - wallet_count: The number of wallets owned by the user.
        - recent_transactions: A list of the user's most recent transactions.
    """
    user_wallets = (
        await database["wallets"].find({"user_id": current_user["_id"]}).to_list(None)
    )

    total_balance = sum(wallet["balance"] for wallet in user_wallets)
    wallet_count = len(user_wallets)

    transactions = (
        await database["transactions"]
        .find({"wallet_id": {"$in": [w["_id"] for w in user_wallets]}})
        .sort("timestamp", -1)
        .limit(5)
        .to_list(None)
    )
    recent_transactions = [
        TransactionResponse(
            id=str(t["_id"]),
            wallet_id=str(t["wallet_id"]),
            amount=t["amount"],
            transaction_type=t["transaction_type"],
            timestamp=t["timestamp"],
        )
        for t in transactions
    ]

    return {
        "total_balance": total_balance,
        "wallet_count": wallet_count,
        "recent_transactions": recent_transactions,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
