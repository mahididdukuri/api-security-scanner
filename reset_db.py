from db import engine
from db_models import Base

#Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

