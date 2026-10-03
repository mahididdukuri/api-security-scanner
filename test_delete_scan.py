from fastapi.testclient import TestClient
from jose import jwt
from api import app
from db import SessionLocal
from db_models import User, Scan
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")

client = TestClient(app)


def make_token(email):
    return jwt.encode({"email": email}, JWT_SECRET, algorithm="HS256")


def create_test_user(email, password="TestPass123!"):
    db = SessionLocal()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        user_id = existing.id
        db.close()
        return email, user_id

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(email=email, password_hash=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id
    db.close()
    return email, user_id


def test_delete_own_scan():
    email, user_id = create_test_user("delete_test_user@example.com")

    db = SessionLocal()
    scan = Scan(target_url="http://127.0.0.1:8004", status="completed", user_id=user_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id
    db.close()

    token = make_token(email)

    response = client.delete(
        f"/scan/{scan_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    print(response.json())
    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_user_cannot_delete_other_users_scan():
    email_a, user_a_id = create_test_user("owner_user@example.com")
    email_b, user_b_id = create_test_user("other_user@example.com")

    db = SessionLocal()
    scan = Scan(target_url="http://127.0.0.1:8004", status="completed", user_id=user_a_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id
    db.close()

    token_b = make_token(email_b)

    response = client.delete(
        f"/scan/{scan_id}",
        headers={"Authorization": f"Bearer {token_b}"}
    )

    assert response.status_code == 404