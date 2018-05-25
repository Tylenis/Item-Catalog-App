from sqlalchemy import Table, Column, ForeignKey, Integer, String
from sqlalchemy import func, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, backref
from itsdangerous import(
    TimedJSONWebSignatureSerializer as Serializer,
    BadSignature, SignatureExpired)
import random
import string

Base = declarative_base()

secret_key = ''.join(
    random.choice(string.ascii_uppercase + string.digits) for x in range(32))


class CategoryMovieLink(Base):
    __tablename__ = "categorymovielink"
    category_id = Column(Integer, ForeignKey("category.id"), primary_key=True)
    movie_id = Column(Integer, ForeignKey("movie.id"), primary_key=True)


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(80), nullable=False, unique=True)
    image = Column(String(250), nullable=True)
    movies = relationship("Movie", backref="user")

    def generate_auth_token(self, expiration=3600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({"id": self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user_id = data["id"]
        return user_id

    @property
    def serialize(self):
        formated_movies = list(
            map(lambda x: x.serialize, self.movies)
        )
        return {
            "user_id": self.id,
            "user_name": self.name,
            "email": self.email,
            "image": self.image,
            "movies": formated_movies
        }


class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    movies = relationship("Movie", secondary="categorymovielink")

    @property
    def serialize(self):
        formated_movies = list(
            map(lambda x: x.serialize, self.movies)
        )
        return {
            "category_id": self.id,
            "category": self.name,
            "movies": formated_movies
        }


class Movie(Base):
    __tablename__ = "movie"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250), nullable=False)
    poster = Column(String(250), nullable=True)
    trailer = Column(String(250), nullable=True)
    created_on = Column(DateTime, default=func.now())
    user_id = Column(Integer, ForeignKey("user.id"))
    categories = relationship("Category", secondary="categorymovielink")

    @property
    def serialize(self):
        formated_categories = list(
            map(lambda x: x.name, self.categories))
        return {
            "movie_id": self.id,
            "movie_title": self.name,
            "description": self.description,
            "poster": self.poster,
            "trailer": self.trailer,
            "categories": formated_categories
        }

engine = create_engine("sqlite:///catalogitems.db")

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
