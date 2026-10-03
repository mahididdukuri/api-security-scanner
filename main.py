from fastapi import FastAPI,HTTPException,Depends,Header

from jose import jwt
# jose is python library for handling JWTs

from datetime import datetime, timedelta,timezone
#timedelta is used for duration of how much time does token be active
# both is used to check token expiry by adding timedelta to current time

app=FastAPI()

SECRET_KEY="my secret"

ALGORITHM="HS256"
def create_token(data:dict):
    to_encode=data.copy()
    expiry=datetime.now(timezone.utc)+timedelta(minutes=30)
    to_encode.update({
        'exp':expiry
    })
    token=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)

    return token

# Login API(Token Generate)

@app.post('/login')
def login(username:str,password:str):
    if username!="mahi" or password!="1234":
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
    token=create_token({
        "sub":username
    })
    return{
        "access_token":token
    }

# Token Verification

def verify_token(token:str=Header(None)):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

# protected route
@app.get('/secure')
def secure_data(user=Depends(verify_token)):
    return{
        "message:Secure Data Accessed"
        "user":user
    }

