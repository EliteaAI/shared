# from ..shared.db_manager import Base, engine
from tools import db


def init_db():
    from .models import vault
    from .models import secrets
    from .models import storage
    db.get_shared_metadata().create_all(bind=db.engine)
