from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import subprocess
import os

# --- Configuration ---
SECRET_KEY = "your_super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = "sqlite:///./users.db"

# --- Database Setup ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

Base.metadata.create_all(bind=engine)

# --- FastAPI App ---
app = FastAPI()

# --- Static Files ---
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return FileResponse(os.path.join("static", "index.html"))

# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str

class UserCreate(User):
    password: str

# --- Utility Functions ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):
    return jwt.encode(data.copy(), SECRET_KEY, algorithm=ALGORITHM)

# --- Create Test User ---
def create_test_user():
    db = SessionLocal()
    if not get_user(db, "admin"):
        hashed = get_password_hash("adminpass")
        user = UserDB(username="admin", hashed_password=hashed)
        db.add(user)
        db.commit()
        print("✅ Created test user: admin / adminpass")
    db.close()

create_test_user()

# --- API Routes ---
@app.post("/register", response_model=User)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if get_user(db, user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    new_user = UserDB(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# --- Server Management ---
SERVERS_START = {
    "godpack": r"S:\Servers\Minecraft\God Pack\minecraft_start.bat",
    "mcally": r"S:\Servers\Minecraft\MCALLY\minecraft_start.bat",
    "cobblemon": r"S:\Servers\Minecraft\Cobblemon\minecraft_start.bat",
    "jujutsukraft": r"S:\Servers\Minecraft\Jujutsu Kraft\minecraft_start.bat",
    "mcsouls": r"S:\Servers\Minecraft\MC Souls\minecraft_start.bat",
    "mcultra": r"S:\Servers\Minecraft\MC Ultra\minecraft_start.bat",
    "mcnf": r"S:\Servers\Minecraft\MCNF\minecraft_start.bat",
    "satisfactory": r"S:\Servers\Satisfactory\satisfactory_start.bat",
    "palworld": r"S:\Servers\PalWorld\palworld_start.bat",
    "terraria": r"S:\Servers\Terraria\terraria_start.bat",
    "stardewvalley": r"S:\Servers\Stardew Valley\stardewvalley_start.bat",
}

SERVERS_STOP = {
    "godpack": r"S:\Servers\Minecraft\God Pack\minecraft_stop.bat",
    "mcally": r"S:\Servers\Minecraft\MCALLY\minecraft_stop.bat",
    "cobblemon": r"S:\Servers\Minecraft\Cobblemon\minecraft_stop.bat",
    "jujutsukraft": r"S:\Servers\Minecraft\Jujutsu Kraft\minecraft_stop.bat",
    "mcsouls": r"S:\Servers\Minecraft\MC Souls\minecraft_stop.bat",
    "mcultra": r"S:\Servers\Minecraft\MC Ultra\minecraft_stop.bat",
    "mcnf": r"S:\Servers\Minecraft\MCNF\minecraft_stop.bat",
    "satisfactory": r"S:\Servers\Satisfactory\satisfactory_stop.bat",
    "palworld": r"S:\Servers\PalWorld\palworld_stop.bat",
    "terraria": r"S:\Servers\Terraria\terraria_stop.bat",
    "stardewvalley": r"S:\Servers\Stardew Valley\stardewvalley_stop.bat",
}

SERVERS_RESTART = {
    "godpack": r"S:\Servers\Minecraft\God Pack\minecraft_restart.bat",
    "mcally": r"S:\Servers\Minecraft\MCALLY\minecraft_restart.bat",
    "cobblemon": r"S:\Servers\Minecraft\Cobblemon\minecraft_restart.bat",
    "jujutsukraft": r"S:\Servers\Minecraft\Jujutsu Kraft\minecraft_restart.bat",
    "mcsouls": r"S:\Servers\Minecraft\MC Souls\minecraft_restart.bat",
    "mcultra": r"S:\Servers\Minecraft\MC Ultra\minecraft_restart.bat",
    "mcnf": r"S:\Servers\Minecraft\MCNF\minecraft_restart.bat",
    "satisfactory": r"S:\Servers\Satisfactory\satisfactory_restart.bat",
    "palworld": r"S:\Servers\PalWorld\palworld_restart.bat",
    "terraria": r"S:\Servers\Terraria\terraria_restart.bat",
    "stardewvalley": r"S:\Servers\Stardew Valley\stardewvalley_restart.bat",
}

def run_bat_file(path: str):
    if not os.path.isfile(path):
        return False, "Batch file not found"
    try:
        subprocess.Popen([path], shell=True)
        return True, "Command executed"
    except Exception as e:
        return False, str(e)

@app.post("/servers/{server_name}/{action}")
async def server_action(
    server_name: str,
    action: str,
    current_user: UserDB = Depends(get_current_user)
):
    server_name = server_name.lower()
    action = action.lower()

    if action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="Invalid action")

    server_map = {
        "start": SERVERS_START,
        "stop": SERVERS_STOP,
        "restart": SERVERS_RESTART
    }

    if server_name not in server_map[action]:
        raise HTTPException(status_code=404, detail="Server not found")

    bat_path = server_map[action][server_name]

    success, message = run_bat_file(bat_path)
    if not success:
        raise HTTPException(status_code=500, detail=message)

    return {"message": message}
