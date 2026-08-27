"""SQLAlchemy declarative base for RedPulse."""

from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase


class Base(AsyncAttrs, DeclarativeBase):
    """SQLAlchemy base class combining AsyncAttrs and DeclarativeBase."""