from fastapi import FastAPI,Header,Depends,HTTPException

from jose import jwt

from datetime import datetime, timedelta,timezone

app=FastAPI()

SECRET_KEY="LOVE"

ALGORITHM="HS256"

@app.post('/login')
def login_page(username:str,password:str,role:str):
    if ((username == "mahi" and password == "1234" and role == "admin") or
        (username == "riya" and password == "5432" and role == "user")):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
    token_value=create_token(
        {
            'sub':username,
            'role':role
        }
    )
    return f"access_token:{token_value}"

def create_token(data:dict):
    to_encode=data.copy()
    expiry=datetime.now(timezone.utc)+timedelta(minutes=30)
    to_encode.update({
        'exp': expiry
    })
    actual_token=jwt.encode(to_encode,SECRET_KEY,ALGORITHM)

    return actual_token

@app.get('/profile')
def profile(token:str=Header(None)):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
    else:
        return{
            'message:'"welcome beautiful",
            'user'==username,
            'role'==role
        }

@app.get('/admin')
def admin(token:str=Header(None)):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        role=payload['role']
        if role!='admin':
            raise HTTPException(
                status_code=403,
                detail="you are not authorized"
            )
        else:
            return {
                "welcome"
            }
    except:
        