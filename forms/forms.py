from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField
from wtforms import widgets, SelectMultipleField
from wtforms.validators import DataRequired, URL, Length

genres = [
    "Action", "Adventure", "Animation", "Comedy", "Crime", "Drama", "Fantasy",
    "Horror", "Mystery", "Romance", "Sci-Fi", "Superhero", "Thriller"]


class MultiCheckBox(SelectMultipleField):
    """Creates checkbox widget, used by CreateForm"""

    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class CreateForm(FlaskForm):
    """Creates form"""

    choices = [(x, x) for x in genres]

    title = StringField(
        "MOVIE TITLE", validators=[DataRequired(), Length(min=2, max=80)])
    description = TextAreaField(
        "DESCRIPTION", validators=[DataRequired(), Length(min=2, max=250)])
    poster = StringField("POSTER URL", validators=[URL()])
    trailer = StringField("TRAILER URL", validators=[URL()])
    categories = MultiCheckBox(
        "CATEGORIES", [DataRequired()],
        choices=choices)
