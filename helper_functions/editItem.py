from models import Movie, Category
from flask_wtf import FlaskForm
import validators


class ValidationException(Exception):
    pass


def editMovie(data, session, item):
    """Edit movie record.

            Args:
                data - instace of FlaskForm or dictionary,
                session - sqlalchemy session object,
                item - instance of Movie
            Returns:
                True for success, error message otherwise.
    """
    try:
        item = item
        if isinstance(data, FlaskForm):
            item.name = data.title.data
            item.description = data.description.data
            item.poster = data.poster.data
            item.trailer = data.trailer.data
            categories = data.categories.data
            item.categories = []
            for category in categories:
                print(category)
                category_obj = session.query(Category).filter_by(
                    name=category).one()
                item.categories.append(category_obj)
        else:
            keys = data.keys()
            for key in keys:
                if key == "name":
                    valid_name = validators.length(data[key], min=2, max=80)
                    if not valid_name:
                        raise ValidationException(
                            "Movie title must be 2-80 charakters long."
                        )
                    else:
                        item.name = data[key]
                if key == "description":
                    valid_description = validators.length(
                        data[key], min=2, max=250)
                    if not valid_description:
                        raise ValidationException(
                            "Movie decription must be 2-250 charakters long."
                        )
                    else:
                        item.description = data[key]
                if key == "poster":
                    valid_poster = validators.url(data[key])
                    if not valid_poster:
                        raise ValidationException("Poster url is not valid.")
                    else:
                        item.poster = data[key]
                if key == "trailer":
                    valid_trailer = validators.url(data[key])
                    if not valid_trailer:
                        raise ValidationException("Trailer url is not valid.")
                    else:
                        item.trailer = data[key]
                if key == "categories":
                    if len(data[key]) == 0:
                        raise ValidationException(
                            "At least one category is required.")
                    else:
                        item.categories = []
                        for category in data[key]:
                            category_obj = session.query(Category).filter_by(
                                name=category).one()
                            item.categories.append(category_obj)
        session.commit()
        return True
    except Exception as e:
        return e
