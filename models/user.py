from sqlalchemy import Column, Integer, String
from config.database import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    points = Column(Integer, default=0)

    def __repr__(self):
        return f"<User(username='{self.username}', points={self.points})>"