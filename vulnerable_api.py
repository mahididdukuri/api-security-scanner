from fastapi import FastAPI, HTTPException, Header

from datetime import datetime, timedelta,timezone

#from fastapi.middleware.cors import CORSMiddleware

from jose import jwt
app=FastAPI()

"""app.add_middleware( # only if we want to allow another origin to access our api
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=['*'],
    allow_headers=["*"]
)"""
users={
    1:{"name":"mahi","email":"abc@example.com" },
    2:{"name":"riya","email":"riya@example.com"},
    3:{"name":"arjun","email":"kkkk@example.com"}
}

users1={}

SECRET_KEY="love"
@app.get("/")
def greet():
    return "Hello Beautiful, Let's get started"

@app.post('/register')
def register(email:str,password:str):
    if (len(password) < 8 or
            not any(c.isupper() for c in password) or
            not any(c.islower() for c in password) or
            not any(c.isdigit() for c in password) or
            not any(not c.isalnum() for c in password)):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 8 characters, one uppercase, one lowercase, one number, and one special character"
        )
    if email in users1:
        return "choose different email"
    users1[email]=password
    return "registered successfully"


login_attempts={}
@app.post('/login')
def login(email:str,password:str):
    login_attempts[email]=login_attempts.get(email,0)+1
    if login_attempts[email]>3:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later."
        )

    expiry=datetime.now(timezone.utc)+timedelta(minutes=2)
    if  email not in users1 or password!=users1[email] :
        raise HTTPException(
            status_code=401,
            detail="wrong credentials"
        )

    token=jwt.encode({"email":email,"exp":expiry},SECRET_KEY,algorithm='HS256')
    return token

def verify_token(token:str):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=['HS256'])
        return payload
    except:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
@app.get('/users/{id}')
def get_id(id:int,authorization:str=Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail='Authorization header missing'
        )
    token=authorization.replace("Bearer ","")
    payload=verify_token(token)
    if id in users:
        if users[id]['email']==payload['email']:
            return users[id]
        else:
            raise HTTPException(
                status_code=403,
                detail="you are not authorized"
            )
        #return users[id]
    else:
         return f"enter valid id"

