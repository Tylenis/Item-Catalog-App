from models import Category, Movie
from flask_wtf import FlaskForm
import validators


class ValidationException(Exception):
    pass


def createMovie(data, session, user):
    """Create movie record.

            Args:
                data - instace of FlaskForm or dictionary.
                session - sqlalchemy session object.
                user - flask session object.
            Returns:
                True for success, error message otherwise.
    """
    try:
        if isinstance(data, FlaskForm):
            movie = Movie(
                name=data.title.data,
                description=data.description.data,
                poster=data.poster.data,
                trailer=data.trailer.data
            )
            categories = data.categories.data
        else:
            if len(data["name"]) < 2 or len(data["name"]) > 80:
                raise ValidationException(
                    "Movie title must be 2-80 charakters long."
                )
            if len(data["description"]) < 2 or len(data["description"]) > 250:
                raise ValidationException(
                    "Movie decription must be 2-250 charakters long."
                )

            valid_poster_url = validators.url(data["poster"])
            valid_trailer_url = validators.url(data["trailer"])

            if not valid_poster_url:
                raise ValidationException("Poster url is not valid.")
            if not valid_trailer_url:
                raise ValidationException("Trailer url is not valid.")

            categories = data["categories"]

            if len(categories) == 0:
                raise ValidationException("At least one category is required.")

            movie = Movie(
                name=data["name"],
                description=data["description"],
                poster=data["poster"],
                trailer=data["trailer"]
            )

        for category in categories:
            category_obj = session.query(Category).filter_by(
                name=category).one()
            movie.categories.append(category_obj)
        movie.user_id = user["user_id"]
        session.add(movie)
        session.commit()
        return True
    except Exception as e:
        return e
