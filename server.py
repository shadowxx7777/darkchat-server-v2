from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime, timedelta
import motor.motor_asyncio
import bcrypt
import jwt
import os
import socketio
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# FastAPI App
app = FastAPI()

# Socket.IO Server
sio = socketio.AsyncServer(async_mode=\
'asgi', cors_allowed_origins="*")
app.mount('/socket.io', socketio.ASGIApp(sio))

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# MongoDB Connection
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/darkchat")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client.darkchat

# JWT Secret
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretjwtkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# Models
class UserInDB(BaseModel):
    id: Optional[str] = Field(alias="_id")
    username: str
    email: str
    hashed_password: str

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
            str: lambda v: str(v) if isinstance(v, motor.core.ObjectId) else v
        }

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserPublic(BaseModel):
    id: str = Field(alias="_id")
    username: str
    email: str

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            str: lambda v: str(v) if isinstance(v, motor.core.ObjectId) else v
        }

class Message(BaseModel):
    id: Optional[str] = Field(alias="_id")
    conversationId: str
    sender: str  # User ID
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    isEdited: bool = False
    isDeleted: bool = False

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
            str: lambda v: str(v) if isinstance(v, motor.core.ObjectId) else v
        }

class Conversation(BaseModel):
    id: Optional[str] = Field(alias="_id")
    participants: List[str]  # List of User IDs
    lastMessage: Optional[str] = None  # Message ID
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
            str: lambda v: str(v) if isinstance(v, motor.core.ObjectId) else v
        }

# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserPublic:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id: str = payload.get("userId")
        if user_id is None:
            raise credentials_exception
        user = await db.users.find_one({"_id": user_id})
        if user is None:
            raise credentials_exception
        return UserPublic(**user)
    except jwt.PyJWTError:
        raise credentials_exception

# Routes
@app.get("/")
async def read_root():
    return {"message": "Dark Chat Server (Python) is running!"}

@app.post("/api/register", response_model=UserPublic)
async def register_user(user_data: UserCreate):
    existing_user = await db.users.find_one({"$or": [{
        "username": user_data.username
    }, {
        "email": user_data.email
    }]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already exists")

    hashed_password = hash_password(user_data.password)
    user_dict = user_data.dict()
    user_dict["hashed_password"] = hashed_password
    del user_dict["password"]

    result = await db.users.insert_one(user_dict)
    new_user = await db.users.find_one({"_id": result.inserted_id})
    return UserPublic(**new_user)

@app.post("/api/login")
async def login_for_access_token(form_data: UserLogin):
    user = await db.users.find_one({"email": form_data.email})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "userId": str(user["_id"]),
            "username": user["username"],
            "email": user["email"]
        },
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "username": user["username"], "email": user["email"], "userId": str(user["_id"])}

@app.get("/api/profile", response_model=UserPublic)
async def get_profile(current_user: UserPublic = Depends(get_current_user)):
    return current_user

@app.get("/api/users/search", response_model=List[UserPublic])
async def search_users(q: str, current_user: UserPublic = Depends(get_current_user)):
    if not q:
        raise HTTPException(status_code=400, detail="Search query is required")
    
    users_cursor = db.users.find({
        "$or": [
            {"username": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}}
        ],
        "_id": {"$ne": current_user.id} # Exclude current user from search results
    }).project({"username": 1, "email": 1})
    
    users = []
    async for user in users_cursor:
        users.append(UserPublic(**user))
    return users

@app.post("/api/conversations")
async def create_conversation(otherUserId: str, current_user: UserPublic = Depends(get_current_user)):
    userId = current_user.id

    existing_conversation = await db.conversations.find_one({
        "participants": {"$all": [userId, otherUserId]}
    })

    if existing_conversation:
        return {"conversationId": str(existing_conversation["_id"])}

    conversation_dict = {"participants": [userId, otherUserId]}
    result = await db.conversations.insert_one(conversation_dict)
    return {"conversationId": str(result.inserted_id)}

@app.get("/api/conversations", response_model=List[Conversation])
async def get_conversations(current_user: UserPublic = Depends(get_current_user)):
    userId = current_user.id
    conversations_cursor = db.conversations.find({"participants": userId}).sort("updatedAt", -1)
    
    conversations = []
    async for conv in conversations_cursor:
        other_user_id = next((p for p in conv["participants"] if p != userId), None)
        other_user = await db.users.find_one({"_id": other_user_id})
        
        last_message = None
        if conv.get("lastMessage"):
            last_message_doc = await db.messages.find_one({"_id": conv["lastMessage"]})
            if last_message_doc:
                last_message = Message(**last_message_doc)

        conversations.append(Conversation(
            id=str(conv["_id"]),
            otherUser=UserPublic(**other_user),
            lastMessage=last_message.id if last_message else None,
            updatedAt=conv["updatedAt"]
        ))
    return conversations

@app.get("/api/conversations/{convId}/messages", response_model=List[Message])
async def get_messages(convId: str, offset: int = 0, limit: int = 50, current_user: UserPublic = Depends(get_current_user)):
    messages_cursor = db.messages.find({"conversationId": convId, "isDeleted": False}).sort("timestamp", 1).skip(offset).limit(limit)
    messages = []
    async for msg in messages_cursor:
        messages.append(Message(**msg))
    return messages

@app.post("/api/conversations/{convId}/messages", response_model=Message)
async def send_message(convId: str, message_data: Dict[str, str], current_user: UserPublic = Depends(get_current_user)):
    senderId = current_user.id
    content = message_data.get("content")

    new_message_dict = {
        "conversationId": convId,
        "sender": senderId,
        "content": content,
        "timestamp": datetime.utcnow()
    }
    result = await db.messages.insert_one(new_message_dict)
    new_message = await db.messages.find_one({"_id": result.inserted_id})

    await db.conversations.update_one(
        {"_id": convId},
        {"$set": {"lastMessage": str(new_message["_id"]), "updatedAt": datetime.utcnow()}}
    )

    # Emit message via Socket.IO
    await sio.emit(
        "new_message",
        {
            "id": str(new_message["_id"]),
            "conversationId": str(new_message["conversationId"]),
            "senderId": str(new_message["sender"]),
            "senderName": current_user.username,
            "content": new_message["content"],
            "timestamp": new_message["timestamp"].isoformat(),
            "isEdited": new_message["isEdited"],
            "isDeleted": new_message["isDeleted"],
        },
        room=convId
    )

    return Message(**new_message)

@app.put("/api/messages/{msgId}", response_model=Message)
async def edit_message(msgId: str, message_data: Dict[str, str], current_user: UserPublic = Depends(get_current_user)):
    userId = current_user.id
    new_content = message_data.get("content")

    message = await db.messages.find_one({"_id": msgId, "sender": userId})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found or not authorized")

    await db.messages.update_one(
        {"_id": msgId},
        {"$set": {"content": new_content, "isEdited": True, "timestamp": datetime.utcnow()}}
    )
    updated_message = await db.messages.find_one({"_id": msgId})

    await sio.emit(
        "message_edited",
        {
            "id": str(updated_message["_id"]),
            "conversationId": str(updated_message["conversationId"]),
            "content": updated_message["content"],
            "isEdited": updated_message["isEdited"],
        },
        room=str(updated_message["conversationId"])
    )

    return Message(**updated_message)

@app.delete("/api/messages/{msgId}")
async def delete_message(msgId: str, current_user: UserPublic = Depends(get_current_user)):
    userId = current_user.id

    message = await db.messages.find_one({"_id": msgId})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    conversation = await db.conversations.find_one({"_id": message["conversationId"]})
    if not conversation or (str(message["sender"]) != userId and userId not in conversation["participants"]):
        raise HTTPException(status_code=403, detail="Not authorized to delete this message")

    await db.messages.update_one(
        {"_id": msgId},
        {"$set": {"isDeleted": True, "content": "This message was deleted.", "timestamp": datetime.utcnow()}}
    )
    deleted_message = await db.messages.find_one({"_id": msgId})

    await sio.emit(
        "message_deleted",
        {
            "id": str(deleted_message["_id"]),
            "conversationId": str(deleted_message["conversationId"]),
            "isDeleted": deleted_message["isDeleted"],
        },
        room=str(deleted_message["conversationId"])
    )

    return {"message": "Message deleted successfully", "id": str(deleted_message["_id"]), "isDeleted": deleted_message["isDeleted"]}

# Socket.IO Events
@sio.event
async def connect(sid, environ, auth):
    print("Socket connected:", sid)
    token = auth.get("token")
    if not token:
        raise ConnectionRefusedError("Authentication token missing")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id = payload.get("userId")
        if user_id is None:
            raise ConnectionRefusedError("Invalid authentication token")
        sio.enter_room(sid, user_id) # User's personal room
        sio.sid_to_user_id[sid] = user_id # Store user_id for later use
        print(f"User {user_id} authenticated with socket {sid}")
        await sio.emit("user_online", {"userId": user_id}, skip_sid=sid) # Notify others
    except jwt.PyJWTError:
        raise ConnectionRefusedError("Invalid authentication token")

@sio.event
async def disconnect(sid):
    print("Socket disconnected:", sid)
    user_id = sio.sid_to_user_id.get(sid)
    if user_id:
        await sio.emit("user_offline", {"userId": user_id}, skip_sid=sid) # Notify others
        del sio.sid_to_user_id[sid]

@sio.event
async def join_conversation(sid, data):
    conversation_id = data.get("conversation_id")
    if conversation_id:
        sio.enter_room(sid, conversation_id)
        print(f"User {sio.sid_to_user_id.get(sid)} joined conversation: {conversation_id}")

@sio.event
async def leave_conversation(sid, data):
    conversation_id = data.get("conversation_id")
    if conversation_id:
        sio.leave_room(sid, conversation_id)
        print(f"User {sio.sid_to_user_id.get(sid)} left conversation: {conversation_id}")

@sio.event
async def typing(sid, data):
    conversation_id = data.get("conversation_id")
    is_typing = data.get("is_typing")
    user_id = sio.sid_to_user_id.get(sid)
    if conversation_id and user_id:
        await sio.emit("typing_status", {"conversationId": conversation_id, "userId": user_id, "isTyping": is_typing}, room=conversation_id, skip_sid=sid)

# Store mapping from sid to user_id for socket events
sio.sid_to_user_id = {}

# Run the app with uvicorn (for local development)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
