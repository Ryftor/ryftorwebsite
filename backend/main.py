from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import Optional
import subprocess

# Secret key for JWT
SECRET_KEY = "your_super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {
    "friend1": {
        "username": "friend1",
        "hashed_password": pwd_context.hash("password123"),
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    # Normally, add expiration, skipping for simplicity
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=username)
    if user is None:
        raise credentials_exception
    return user

# Define the batch file paths for each server
SERVERS_START = {
    "godpack": r"S:\Servers\Minecraft\God Pack\minecraft _start.bat",
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
    # Add other servers as needed
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
    # Add other servers as needed
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
    # Add other servers as needed
}

def run_batch_file(path: str):
    try:
        subprocess.Popen([path], shell=True)
        return True, None
    except Exception as e:
        return False, str(e)

@app.post("/servers/{server_name}/start")
async def start_server(server_name: str, user: User = Depends(get_current_user)):
    if server_name not in SERVERS_START:
        raise HTTPException(status_code=404, detail="Server not found")
    success, error = run_batch_file(SERVERS_START[server_name])
    if not success:
        return {"error": error}
    return {"message": f"Starting {server_name}"}

@app.post("/servers/{server_name}/stop")
async def stop_server(server_name: str, user: User = Depends(get_current_user)):
    if server_name not in SERVERS_STOP:
        raise HTTPException(status_code=404, detail="Server not found")
    success, error = run_batch_file(SERVERS_STOP[server_name])
    if not success:
        return {"error": error}
    return {"message": f"Stopping {server_name}"}

@app.post("/servers/{server_name}/restart")
async def restart_server(server_name: str, user: User = Depends(get_current_user)):
    if server_name not in SERVERS_RESTART:
        raise HTTPException(status_code=404, detail="Server not found")
    success, error = run_batch_file(SERVERS_RESTART[server_name])
    if not success:
        return {"error": error}
    return {"message": f"Restarting {server_name}"}
