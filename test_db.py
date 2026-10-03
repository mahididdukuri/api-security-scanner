from db import SessionLocal
from db_models import Scan

db=SessionLocal()

scan=Scan(
    target_url="http://127.0.0.1:8004",
    status='completed'
)

db.add(scan)
db.commit()
db.refresh(scan)

print(scan.id)

db.close()