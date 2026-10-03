from fastapi import FastAPI, BackgroundTasks,Header,HTTPException
from pydantic import BaseModel

from db import SessionLocal
from db_models import Scan,User

from scanner import run_scan
import config
import bcrypt
from jose import jwt,JWTError
import os
from dotenv import load_dotenv

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")

app = FastAPI()


class RegisterRequest(BaseModel):
    email:str
    password:str
@app.post('/register')
def register(request:RegisterRequest):
    db=SessionLocal()
    existing_user=db.query(User).filter(User.email==request.email).first()
    if existing_user:
        db.close()
        raise HTTPException(
            status_code=400,
            detail="This email is already registered"
        )
    # Hash password

    hashed_password=bcrypt.hashpw(
        request.password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    # Create user
    user=User(
        email=request.email,
        password_hash=hashed_password
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    db.close()

    return{
        "message": "User registered successfully",
        "user_id": user.id,
        "email": user.email
    }
class LoginRequest(BaseModel):
    email:str
    password:str

@app.post('/login')
def login(request:LoginRequest):
    db=SessionLocal()
    is_user=db.query(User).filter(User.email==request.email).first()
    if not is_user:
        raise HTTPException(
            status_code=404,
            detail="this email is not existed, register "
        )
    else:
        is_valid=bcrypt.checkpw(
            request.password.encode('utf-8'),
            is_user.password_hash.encode('utf-8')
        )
        if not is_valid:
            raise HTTPException(
                status_code=401,
                detail="Incorrect password"
            )
        data={"email":is_user.email}
        token=jwt.encode(data,JWT_SECRET,algorithm='HS256')

        return {
            "access_token":token,
            "token_type":"bearer"
        }

def validate_token(token):
    try:
       data=jwt.decode(token,JWT_SECRET,algorithms=["HS256"])
       return data
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )


class ScanRequest(BaseModel):
    target_url: str

def run_scan_background(scan_id):
    run_scan(scan_id)
@app.post("/scan")
def scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    authorization: str = Header(None)
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )
    #target_url = request.target_url
    token = authorization.replace("Bearer ", "")

    data = validate_token(token)
    db = SessionLocal()
    current_user = db.query(User).filter(
        User.email == data["email"]
    ).first()
    config.BASE_URL=request.target_url

    scan_record = Scan(
        target_url=config.BASE_URL,
        status="running",
        user_id=current_user.id
    )

    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    scan_id= scan_record.id
    db.close()
    background_tasks.add_task(run_scan_background,scan_id)
    #result = run_scan(target_url)
    #result=run_scan()
    return {
        "status": "started",
        "scan_id": scan_id,
        "target": config.BASE_URL,
        #"findings": result
    }

@app.get("/scan/{scan_id}")
def get_scan(scan_id: int, authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    data = validate_token(token)
    db = SessionLocal()
    current_user = db.query(User).filter(
        User.email == data["email"]
    ).first()
    scan =  db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()

    if not scan:
        db.close()
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    result = {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "findings": [],
        "risk_score": scan.risk_score
    }

    for finding in scan.findings:
        result["findings"].append({
            "name": finding.name,
            "status": finding.status,
            "severity": finding.severity,
            "description": finding.description,
            "confidence": finding.confidence
        })

    db.close()

    return result

@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: int, authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    data = validate_token(token)

    db = SessionLocal()

    current_user = db.query(User).filter(
        User.email == data["email"]
    ).first()

    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()

    if not scan:
        db.close()
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    db.delete(scan)
    db.commit()
    db.close()

    return {
        "message": "Scan deleted successfully",
        "scan_id": scan_id
    }

@app.get("/scans")
def scans(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    data = validate_token(token)
    db=SessionLocal()
    current_user = db.query(User).filter(
        User.email == data["email"]
    ).first()
    scans=db.query(Scan).filter(
        Scan.user_id == current_user.id
    ).all()
    result=[]
    for scan in scans:
        result.append({
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status,
            "risk_score": scan.risk_score
        })
    db.close()
    return result

