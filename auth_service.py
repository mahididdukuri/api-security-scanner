from fastapi import FastAPI,HTTPException, Header,Depends
import bcrypt
from jose import jwt
from datetime import datetime, timedelta, timezone

app=FastAPI()

username={}

SECRET_KEY="my-super-secret-key"

@app.post('/register')
def register(name:str,password:str,email:str):
    if name in username:
        return {"message": "choose a different name"}
    else:
        hashed_password=bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        )
        username[name]={"password":hashed_password,"email":email}
        return {"message": "registered successfully"}

@app.post('/login')
def login(name:str,password:str):
    if name in username and bcrypt.checkpw(
        password.encode(),
        username[name]["password"]
    ):
        expire=datetime.now(timezone.utc)+timedelta(minutes=30)
        token=jwt.encode({
            "name":name,
            "email":username[name]["email"],
            "exp":expire
            },
            SECRET_KEY,
            algorithm='HS256'
        )
        return token
    else:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

@app.get('/profile')
def profile(token:str=Header(None)):
    try:
        payload=jwt.decode(
            token,SECRET_KEY,algorithms=['HS256']
        )
        return payload
    except:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
