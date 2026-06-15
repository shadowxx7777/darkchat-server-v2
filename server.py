
import os
import asyncio
import secrets
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Annotated

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict, BeforeValidator, PlainSerializer
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from passlib.context import CryptContext
from jose import JWTError, jwt
import socketio
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText

# Load environment variables from .env file
load_dotenv()

# --- Configuration --- #
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM")
VERIFICATION_TOKEN_EXPIRE_MINUTES = 60
MONGO_DETAILS = os.getenv("MONGODB_URI")
JWT_SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- FastAPI App Setup --- #
app = FastAPI(
    title="Dark Chat Server (Python)",
    description="Real-time chat application backend with FastAPI, MongoDB, and Socket.IO",
    version="1.0.0",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Socket.IO Setup
sio = socketio.AsyncServer(cors_allowed_origins="*", async_mode="asgi")
app.mount("/ws", socketio.ASGIApp(sio))

# --- Database Setup --- #
# Use a string representation for ObjectId in models to avoid Pydantic v2 issues
# We will convert to/from ObjectId when interacting with the database

class MongoDBModel(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

client = AsyncIOMotorClient(MONGO_DETAILS)
database = client.darkchat
users_collection = database.get_collection("users")
conversations_collection = database.get_collection("conversations")
messages_collection = database.get_collection("messages")
groups_collection = database.get_collection("groups")

# Helper to convert MongoDB document to model-friendly dict
def fix_doc(doc):
    if doc and "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc

# --- Security --- #
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_verification_token(email: str, expires_delta: Optional[timedelta] = None):
    to_encode = {"sub": email, "type": "email_verification"}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=VERIFICATION_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def send_verification_email(email: str, username: str, token: str):
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM]):
        print("SMTP configuration missing. Skipping email verification.")
        return

    verification_link = f"http://localhost:8000/api/verify-email?token={token}" # TODO: Replace with actual deployed server URL
    subject = "DarkChat Email Verification"
    body = f"Hello {username},\n\nThank you for registering with DarkChat. Please click the link below to verify your email address:\n\n{verification_link}\n\nThis link will expire in {VERIFICATION_TOKEN_EXPIRE_MINUTES} minutes.\n\nBest regards,\nDarkChat Team"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Verification email sent to {email}")
    except Exception as e:
        print(f"Failed to send verification email to {email}: {e}")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise credentials_exception
    return UserInDB(**fix_doc(user))

# --- Models --- #
class UserBase(BaseModel):
    email: str
    username: str

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase, MongoDBModel):
    hashed_password: str
    dc_id: str = Field(default_factory=lambda: ".".join(secrets.token_hex(2).upper() for _ in range(2)))
    avatar_url: Optional[str] = None
    is_online: bool = False
    email_verified: bool = False
    blocked_users: List[str] = []
    muted_users: List[str] = []

class UserPublic(UserBase, MongoDBModel):
    dc_id: str
    avatar_url: Optional[str] = None
    is_online: bool
    email_verified: bool

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserPublic

class MessageBase(BaseModel):
    content: str

class MessageCreate(MessageBase):
    conversation_id: Optional[str] = None
    group_id: Optional[str] = None
    sender_id: str
    sender_name: str
    sender_avatar: Optional[str] = None
    is_edited: bool = False
    is_deleted: bool = False

class MessageInDB(MessageCreate, MongoDBModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class MessagePublic(MessageInDB):
    pass

class ConversationBase(BaseModel):
    participants: List[str]

class ConversationCreate(BaseModel):
    other_user_id: str

class ConversationInDB(ConversationBase, MongoDBModel):
    last_message: Optional[MessagePublic] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ConversationPublic(ConversationInDB):
    other_user: UserPublic

class GroupBase(BaseModel):
    name: str
    description: Optional[str] = None
    members: List[str]

class GroupCreate(GroupBase):
    pass

class GroupInDB(GroupBase, MongoDBModel):
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_message: Optional[MessagePublic] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class GroupPublic(GroupInDB):
    pass

class CallOffer(BaseModel):
    caller_id: str
    caller_name: str
    callee_id: str
    sdp: str
    type: str

class CallAnswer(BaseModel):
    answerer_id: str
    answerer_name: str
    caller_id: str
    sdp: str
    type: str

class IceCandidate(BaseModel):
    sender_id: str
    receiver_id: str
    candidate: str
    sdp_mid: str
    sdp_m_line_index: int

# --- API Endpoints --- #
@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Dark Chat Server (Python) is running!"}

@app.post("/api/register", response_model=Token, tags=["Auth"])
async def register_user(user_data: UserCreate):
    existing_user = await users_collection.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    hashed_password = get_password_hash(user_data.password)
    user_in_db = UserInDB(email=user_data.email, username=user_data.username, hashed_password=hashed_password)
    user_in_dict = user_in_db.model_dump(by_alias=True, exclude={"id"})
    new_user = await users_collection.insert_one(user_in_dict)
    
    # Send verification email
    verification_token = create_verification_token(user_data.email)
    await send_verification_email(user_data.email, user_data.username, verification_token)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(new_user.inserted_id)},
        expires_delta=access_token_expires
    )
    user_public = UserPublic(**user_in_dict, _id=str(new_user.inserted_id))
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": user_public
    }

@app.get("/api/verify-email", tags=["Auth"])
async def verify_email(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        if email is None or token_type != "email_verification":
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await users_collection.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    await users_collection.update_one({"email": email}, {"$set": {"email_verified": True}})
    return {"message": "Email verified successfully! You can now log in."}

@app.post("/api/resend-verification-email", status_code=status.HTTP_204_NO_CONTENT, tags=["Auth"])
async def resend_verification_email(current_user: UserInDB = Depends(get_current_user)):
    if current_user.email_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already verified")
    
    verification_token = create_verification_token(current_user.email)
    await send_verification_email(current_user.email, current_user.username, verification_token)
    return

@app.post("/api/login", response_model=Token, tags=["Auth"])
async def login_for_access_token(user_data: UserCreate):
    user = await users_collection.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["_id"])}
    )
    user_public = UserPublic(**fix_doc(user))
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": user_public
    }

@app.get("/api/profile", response_model=UserPublic, tags=["Users"])
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return UserPublic(**current_user.model_dump())

@app.get("/api/users/search", response_model=List[UserPublic], tags=["Users"])
async def search_users(q: str, current_user: UserInDB = Depends(get_current_user)):
    users = await users_collection.find({
        "$or": [
            {"username": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
            {"dc_id": q} # Search by unique ID
        ],
        "_id": {"$ne": ObjectId(current_user.id)} # Exclude current user
    }).to_list(length=10)
    return [UserPublic(**fix_doc(user)) for user in users]

@app.post("/api/conversations", response_model=Dict[str, str], tags=["Conversations"])
async def create_conversation(conv_data: ConversationCreate, current_user: UserInDB = Depends(get_current_user)):
    other_user_obj_id = ObjectId(conv_data.other_user_id)
    if str(other_user_obj_id) == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot create conversation with self")

    # Check if conversation already exists
    existing_conv = await conversations_collection.find_one({
        "participants": {"$all": [ObjectId(current_user.id), other_user_obj_id]}
    })
    if existing_conv:
        return {"conversationId": str(existing_conv["_id"])}

    conversation = ConversationInDB(participants=[current_user.id, conv_data.other_user_id])
    new_conv = await conversations_collection.insert_one({
        "participants": [ObjectId(current_user.id), other_user_obj_id],
        "updated_at": datetime.utcnow()
    })
    return {"conversationId": str(new_conv.inserted_id)}

@app.get("/api/conversations", response_model=List[ConversationPublic], tags=["Conversations"])
async def get_conversations(current_user: UserInDB = Depends(get_current_user)):
    conversations = await conversations_collection.find({"participants": ObjectId(current_user.id)}).sort("updated_at", -1).to_list(length=100)
    
    result = []
    for conv_data in conversations:
        other_user_id = next(p for p in conv_data["participants"] if str(p) != current_user.id)
        other_user = await users_collection.find_one({"_id": other_user_id})
        if other_user:
            conv_public = ConversationPublic(**fix_doc(conv_data), other_user=UserPublic(**fix_doc(other_user)))
            result.append(conv_public)
    return result

@app.get("/api/messages", response_model=List[MessagePublic], tags=["Messages"])
async def get_messages(target_id: str, is_group: bool = False, offset: int = 0, limit: int = 50, current_user: UserInDB = Depends(get_current_user)):
    target_obj_id = ObjectId(target_id)
    
    if is_group:
        group = await groups_collection.find_one({"_id": target_obj_id, "members": ObjectId(current_user.id)})
        if not group:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found or not a member")
        query = {"group_id": target_id}
    else:
        # Check if conversation exists and user is participant
        conv = await conversations_collection.find_one({"_id": target_obj_id, "participants": ObjectId(current_user.id)})
        if not conv:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found or not a participant")
        query = {"conversation_id": target_id}
    
    messages = await messages_collection.find(query).sort("timestamp", -1).skip(offset).limit(limit).to_list(length=limit)
    return [MessagePublic(**fix_doc(msg)) for msg in messages]

@app.post("/api/messages", response_model=MessagePublic, tags=["Messages"])
async def send_message(message_data: MessageCreate, current_user: UserInDB = Depends(get_current_user)):
    if not message_data.conversation_id and not message_data.group_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Either conversation_id or group_id must be provided")

    if message_data.conversation_id:
        target_id = message_data.conversation_id
        is_group = False
        # Verify conversation
        conv = await conversations_collection.find_one({"_id": ObjectId(target_id), "participants": ObjectId(current_user.id)})
        if not conv:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a participant in this conversation")
    else:
        target_id = message_data.group_id
        is_group = True
        # Verify group
        group = await groups_collection.find_one({"_id": ObjectId(target_id), "members": ObjectId(current_user.id)})
        if not group:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this group")

    message_dict = message_data.model_dump()
    message_dict["sender_id"] = current_user.id
    message_dict["sender_name"] = current_user.username
    message_dict["timestamp"] = datetime.utcnow()
    
    new_msg = await messages_collection.insert_one(message_dict)
    msg_public = MessagePublic(**message_dict, _id=str(new_msg.inserted_id))

    # Update conversation/group timestamp
    update_data = {"updated_at": datetime.utcnow(), "last_message": msg_public.model_dump(mode='json')}
    if is_group:
        await groups_collection.update_one({"_id": ObjectId(target_id)}, {"$set": update_data})
        room = "group_" + target_id
    else:
        await conversations_collection.update_one({"_id": ObjectId(target_id)}, {"$set": update_data})
        other_user_id = next(str(p) for p in conv["participants"] if str(p) != current_user.id)
        room = other_user_id

    # Emit via Socket.IO
    await sio.emit("new_message", msg_public.model_dump(mode='json'), room=room)
    return msg_public

@app.put("/api/messages/{message_id}", response_model=MessagePublic, tags=["Messages"])
async def edit_message(message_id: str, content: str, current_user: UserInDB = Depends(get_current_user)):
    msg = await messages_collection.find_one({"_id": ObjectId(message_id), "sender_id": current_user.id})
    if not msg:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found or not the sender")
    
    await messages_collection.update_one({"_id": ObjectId(message_id)}, {"$set": {"content": content, "is_edited": True}})
    updated_msg = await messages_collection.find_one({"_id": ObjectId(message_id)})
    msg_public = MessagePublic(**fix_doc(updated_msg))
    
    # Notify via Socket.IO
    room = msg.get("group_id") if msg.get("group_id") else msg.get("conversation_id")
    await sio.emit("message_edited", msg_public.model_dump(mode='json'), room=room)
    return msg_public

@app.delete("/api/messages/{message_id}", tags=["Messages"])
async def delete_message(message_id: str, current_user: UserInDB = Depends(get_current_user)):
    msg = await messages_collection.find_one({"_id": ObjectId(message_id), "sender_id": current_user.id})
    if not msg:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found or not the sender")
    
    await messages_collection.delete_one({"_id": ObjectId(message_id)})
    
    # Notify via Socket.IO
    room = msg.get("group_id") if msg.get("group_id") else msg.get("conversation_id")
    await sio.emit("message_deleted", {"message_id": message_id, "room": room}, room=room)
    return {"message": "Message deleted"}

@app.post("/api/groups", response_model=GroupPublic, tags=["Groups"])
async def create_group(group_data: GroupCreate, current_user: UserInDB = Depends(get_current_user)):
    group_dict = group_data.model_dump()
    group_dict["members"] = [ObjectId(current_user.id)]
    group_dict["created_by"] = current_user.id
    group_dict["created_at"] = datetime.utcnow()
    group_dict["updated_at"] = datetime.utcnow()
    
    new_group = await groups_collection.insert_one(group_dict)
    return GroupPublic(**fix_doc(group_dict), _id=str(new_group.inserted_id))

@app.get("/api/groups", response_model=List[GroupPublic], tags=["Groups"])
async def get_groups(current_user: UserInDB = Depends(get_current_user)):
    groups = await groups_collection.find({"members": ObjectId(current_user.id)}).sort("updated_at", -1).to_list(length=100)
    return [GroupPublic(**fix_doc(g)) for g in groups]

@app.post("/api/groups/{group_id}/join", tags=["Groups"])
async def join_group(group_id: str, current_user: UserInDB = Depends(get_current_user)):
    group = await groups_collection.find_one({"_id": ObjectId(group_id)})
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    
    if ObjectId(current_user.id) in group["members"]:
        return {"message": "Already a member"}
    
    await groups_collection.update_one({"_id": ObjectId(group_id)}, {"$push": {"members": ObjectId(current_user.id)}})
    return {"message": "Joined group successfully"}

@app.post("/api/users/{user_id}/block", tags=["Privacy"])
async def block_user(user_id: str, current_user: UserInDB = Depends(get_current_user)):
    target_obj_id = ObjectId(user_id)
    if str(target_obj_id) == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot block self")
    
    await users_collection.update_one({"_id": ObjectId(current_user.id)}, {"$addToSet": {"blocked_users": user_id}})
    return {"message": "User blocked"}

@app.delete("/api/users/{user_id}/block", tags=["Privacy"])
async def unblock_user(user_id: str, current_user: UserInDB = Depends(get_current_user)):
    await users_collection.update_one({"_id": ObjectId(current_user.id)}, {"$pull": {"blocked_users": user_id}})
    return {"message": "User unblocked"}

# --- Socket.IO Events --- #
@sio.on("connect")
async def connect(sid, environ):
    # In a real app, verify JWT from headers/query
    print(f"Client connected: {sid}")

@sio.on("join")
async def join(sid, data):
    user_id = data.get("userId")
    if user_id:
        sio.enter_room(sid, user_id)
        # Also join group rooms
        user_groups = await groups_collection.find({"members": ObjectId(user_id)}).to_list(length=None)
        for group in user_groups:
            sio.enter_room(sid, "group_" + str(group["_id"]))
        print(f"User {user_id} joined room")

@sio.on("disconnect")
async def disconnect(sid):
    print(f"Client disconnected: {sid}")
    # Leave all rooms
    rooms = sio.rooms(sid)
    for room in rooms:
        if room != sid:
            sio.leave_room(sid, room)

@sio.on("call_offer")
async def handle_call_offer(sid, data):
    offer = CallOffer(**data)
    await sio.emit("call_offer", offer.model_dump(), room=offer.callee_id)

@sio.on("call_answer")
async def handle_call_answer(sid, data):
    answer = CallAnswer(**data)
    await sio.emit("call_answer", answer.model_dump(), room=answer.caller_id)

@sio.on("ice_candidate")
async def handle_ice_candidate(sid, data):
    candidate = IceCandidate(**data)
    await sio.emit("ice_candidate", candidate.model_dump(), room=candidate.receiver_id)

@sio.on("call_end")
async def handle_call_end(sid, data):
    callee_id = data.get("callee_id")
    caller_id = data.get("caller_id")
    if callee_id:
        await sio.emit("call_end", {"caller_id": caller_id}, room=callee_id)
    if caller_id:
        await sio.emit("call_end", {"callee_id": callee_id}, room=caller_id)

@sio.on("typing")
async def typing(sid, data):
    user_id = data.get("userId")
    target_id = data.get("targetId")
    is_group = data.get("isGroup", False)
    if user_id and target_id:
        room = "group_" + target_id if is_group else target_id
        await sio.emit("typing", {"userId": user_id, "isTyping": True}, room=room, skip_sid=sid)

# --- Background Task: Render Pulse --- #
async def render_pulse():
    """Keep the server alive on Render free tier."""
    while True:
        await asyncio.sleep(600) # Every 10 minutes
        print("Pulse: Keeping server alive...")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(render_pulse())
