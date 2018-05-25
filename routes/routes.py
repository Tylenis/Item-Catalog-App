import httplib2
import random
import string
import json
import requests

from flask import (
    render_template, jsonify, make_response, request, redirect,
    Response, url_for)
from flask.views import View, MethodView
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy.orm.exc import NoResultFound

from models import User, Movie, Category
from helper_functions import createMovie, editMovie
from forms import CreateForm


class TemplateView(View):
    """Template for CRUD views"""

    def __init__(self, session, login_session, auth_required=False):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
                auth_required: Boolean, default=False.

        """
        self.session = session
        self.login_session = login_session
        self.auth_required = auth_required

# Raise error if child class does not have 'get_template_name' method
    def get_template_name(self):
        raise NotImplementedError()

    def dispatch_request(self, **kwargs):
        if self.auth_required and self.login_session.get("user_id"):
            if kwargs:
                value = list(kwargs.values())[0]
                context = self.get_context(value)
            else:
                context = self.get_context()
            if context["error"]:
                return render_template("error.html", context=context)
            elif context["redirect_to_main"]:
                return redirect(url_for("mainView"))
            else:
                template = self.get_template_name()
                return render_template(template, context=context)
        elif self.auth_required and self.login_session.get("user_id") is None:
            return redirect(url_for("mainView"))
        else:
            if kwargs:
                value = list(kwargs.values())[0]
                context = self.get_context(value)
            else:
                context = self.get_context()
            if context["error"]:
                return render_template("error.html", context=context)
            elif context["redirect_to_main"]:
                return redirect(url_for("mainView"))
            else:
                template = self.get_template_name()
                return render_template(template, context=context)


# ---------------------AUTHORIZATION---------------------------------

class LoginView(TemplateView):
    """Handles GET request for '/catalog/login'"""

    def get_template_name(self):
        return "login.html"

    def gen_csfr_token(self):
        token = "".join(
            random.choice(string.ascii_uppercase + string.digits)
            for x in range(32)
        )
        return token

    def get_context(self):
        context = {
            "user": self.login_session,
            "auth_required": False,
            "error": False,
            "redirect_to_main": False
        }
        try:
            token = self.gen_csfr_token()
            self.login_session["CSFR_TOKEN"] = token
            context["CSFR_TOKEN"] = token
        except Exception as e:
            context["error"] = True
            context["msg"] = e
        return context


class GoogleLogin(MethodView):
    """Handles user authentication"""

    def __init__(self, session, login_session, client_secrets, client_id):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
                client_secrets: path to 'client_secrets.json' file.
                client_id: integer.

        """
        self.session = session
        self.login_session = login_session
        self.client_secret_file = client_secrets
        self.client_id = client_id

    def validate_header(self):
        """Validate 'X-Requested-With' header

        Returns:
            True for success, 401 response otherwise.
        """

        if not request.headers.get("X-Requested-With"):
            response = make_response(
                json.dumps("Header 'X-Requested-With' is missing."), 401
            )
            response.headers["Content-Type"] = "application/json"
            return response
        return True

    def validate_csfr_token(self):
        """Validate 'CSFR' token

        Returns:
            request.data for success, 401 response otherwise.
        """
        if request.args.get("state") != self.login_session["CSFR_TOKEN"]:
            response = make_response(
                json.dumps("Invalid state parameter."),
                401
            )
            response.headers["Content-Type"] = "application/json"
            return response
        return request.data

    def code_to_credentials(self, code):
        """Upgrade the authorization code into a credentials object

            Args:
                code - code provided by Google.
            Returns:
                Credentials for success, 401 response otherwise.
        """

        try:
            oauth_flow = flow_from_clientsecrets(
                self.client_secret_file, scope="")
            oauth_flow.redirect_uri = "postmessage"
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                json.dumps("Failed to upgrade authorization code."), 401)
            response.headers["Content-Type"] = "application/json"
            return response
        return credentials

    def check_access_token(self, credentials):
        """Check the access token is valid.

            Args:
                credentials - credentials.
            Returns:
                User profile dictionary, 401 response otherwise.
        """
        access_token = credentials.access_token
        url = (
            "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s"
            % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, "GET")[1])
        if result.get("error") is not None:
            response = make_response(
                json.dumps(result.get("error")), 500)
            response.headers["Content-Type"] = "application/json"
            return response
        return result

    def check_user(self, credentials, result):
        """Verify the access token is used for the intended user.

            Args:
                credentials - credentials.
                result - user profile dictionary
            Returns:
                User gplus id, 401 response otherwise.

        """
        gplus_id = credentials.id_token["sub"]
        if result["user_id"] != gplus_id:
            response = make_response(
                json.dumps(
                    "Token's user ID doesn't match given user ID."), 401)
            response.headers["Content-Type"] = "application/json"
            return response
        return gplus_id

    def check_app(self, result):
        """Verify the access token is valid for this app.

            Args:
                result - user profile dictionary
            Returns:
                True, 500 response otherwise.
        """
        if result["issued_to"] != self.client_id:
            response = make_response(
                json.dumps("Token's client ID does not match app's."), 500)
            response.headers["Content-Type"] = "application/json"
            return response
        return True

    def check_connected(self, stored_token, gplus_id, stored_gplus_id):
        """Verify if user is already connected.

            Args:
                stored_token - token stored in flask session.
                gplus_id - user gplus id
                stored_gplus_id - gplus_id stored in flask session
            Returns:
                response 200, False otherwise.
        """
        if stored_token is not None and gplus_id == stored_gplus_id:
            response = make_response(
                json.dumps("Current user is already connected."), 200)
            response.headers["Content-Type"] = "application/json"
            return response
        return False

    def get_user_info(self, credentials):
        """Get user info

            Args:
                credentials - credentials
            Returns:
                User profile data, False 401 response otherwise.
        """
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        try:
            params = {"access_token": credentials.access_token, "alt": "json"}
            answer = requests.get(userinfo_url, params=params)
            data = answer.json()
        except Exception as e:
            response = make_response(
                json.dumps(
                    "Could not get user info."), 401)
            response.headers["Content-Type"] = "application/json"
            return response
        return data

    def create_user(self, data):
        """Create the user profile in the database.

            Args:
                data - user profile data.
            Returns:
                true, False 500 response otherwise.
        """
        try:
            user_in_db = self.session.query(User).filter_by(
                email=data["email"]).first()
            if user_in_db is None:
                user = User(
                    name=data["name"],
                    image=data["picture"],
                    email=data["email"]
                )
                self.session.add(user)
                self.session.commit()
                self.login_session["user_id"] = user.id
                if self.login_session.get("API_TOKEN"):
                    self.login_session["API_TOKEN"] = None
            else:
                self.login_session["user_id"] = user_in_db.id
        except Exception as e:
            response = make_response(
                json.dumps(e, 500))
            response.headers["Content-Type"] = "application/json"
            return response
        return True

    def post(self):
        # Validate 'X-Requested-With' header
        valid_header_result = self.validate_header()
        if isinstance(valid_header_result, Response):
            return valid_header_result

        # Validate CSFR token
        valid_csfr_token_result = self.validate_csfr_token()
        if isinstance(valid_csfr_token_result, Response):
            return valid_csfr_token_result

        code = valid_csfr_token_result

        # Upgrade the authorization code into a credentials object
        code_to_credentials_result = self.code_to_credentials(code)
        if isinstance(code_to_credentials_result, Response):
            return code_to_credentials_result
        credentials = code_to_credentials_result

        # Check that the access token is valid.
        check_access_token_result = self.check_access_token(credentials)
        if isinstance(check_access_token_result, Response):
            return check_access_token_result

        # Verify the access token is used for the intended user.
        check_user_result = self.check_user(
            credentials, check_access_token_result)
        if isinstance(check_user_result, Response):
            return check_user_result
        gplus_id = check_user_result

        # Verify the access token is valid for this app.
        check_app_result = self.check_app(check_access_token_result)
        if isinstance(check_app_result, Response):
            return check_app_result

        stored_access_token = self.login_session.get("access_token")
        stored_gplus_id = self.login_session.get("gplus_id")

        # Verify if user is already connected.
        check_connected_result = self.check_connected(
            stored_access_token, gplus_id, stored_gplus_id)
        if isinstance(check_connected_result, Response):
            return check_connected_result

        # Store the access token in the session for later use.
        self.login_session["access_token"] = credentials.access_token
        self.login_session["gplus_id"] = gplus_id

        # Get user info
        get_user_info_result = self.get_user_info(credentials)
        if isinstance(get_user_info_result, Response):
            return get_user_info_result
        data = get_user_info_result

        # Store the user profile data in the session for later use.
        self.login_session["username"] = data["name"]
        self.login_session["picture"] = data["picture"]
        self.login_session["email"] = data["email"]

        # Strore the user profile data in the database
        create_user_result = self.create_user(data)
        if isinstance(create_user_result, Response):
            return create_user_result

        response = make_response(
            json.dumps("User logged in successfully!"),
            200
        )
        return response


class GoogleLogout(MethodView):
    """Handles user logout"""

    def __init__(self, login_session, auth_required=False):
        """
            Args:
                login_session: flask session object.
                auth_required: Boolean, default=False.

        """
        self.login_session = login_session
        self.auth_required = auth_required

    def post(self):
        # Revoke access token
        if self.auth_required and self.login_session.get("user_id"):
            requests.post(
                "https://accounts.google.com/o/oauth2/revoke",
                params={"token": self.login_session.get("access_token")},
                headers={"content-type": "application/x-www-form-urlencoded"})

            # Delete all data from session
            del self.login_session["username"]
            del self.login_session["picture"]
            del self.login_session["email"]
            del self.login_session["access_token"]
            del self.login_session["gplus_id"]
            del self.login_session["CSFR_TOKEN"]
            del self.login_session["user_id"]

            response = make_response(
                json.dumps("Logout success"), 200
            )
            response.headers["Content-Type"] = "application/json"
        else:
            response = make_response(
                json.dumps("Unauthorized access denied."),
                401
            )
            response.headers["Content-Type"] = "application/json"
        return response


class DeleteAccount(MethodView):
    """Delete account"""

    def __init__(self, login_session, session):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
        """
        self.login_session = login_session
        self.session = session

    def post(self, user_id):
        if self.login_session.get("user_id") == user_id:
            try:
                user = self.session.query(User).filter_by(id=user_id).one()
                self.session.delete(user)
                self.session.commit()
                del self.login_session["username"]
                del self.login_session["picture"]
                del self.login_session["email"]
                del self.login_session["access_token"]
                del self.login_session["gplus_id"]
                del self.login_session["CSFR_TOKEN"]
                del self.login_session["user_id"]
                if self.login_session.get("API_TOKEN"):
                    del self.login_session["API_TOKEN"]
            except Exception as e:
                response = make_response(
                    json.dumps({"error": str(e)}),
                    401
                )
                response.headers["Content-Type"] = "application/json"
                return response
            return redirect(url_for("mainView"))
        else:
            response = make_response(
                json.dumps("Unauthorized access denied."),
                401
            )
            response.headers["Content-Type"] = "application/json"
            return response


# -------------------------CRUD--------------------------------------


class MainView(TemplateView):
    """Handles GET request for '/'"""

    def get_template_name(self):
        return "main.html"

    def get_context(self):
        context = {
            "user": self.login_session,
            "error": False,
            "redirect_to_main": False
        }
        try:
            categories = self.session.query(Category).all()
            recent_items = self.session.query(Movie).order_by(
                Movie.created_on.desc()).limit(5)
            context["categories"] = categories
            context["movies"] = recent_items
        except Exception as e:
            context["error"] = True
            context["msg"] = e
        return context


class CategoryView(TemplateView):
    """Handles GET request for '/catalog/<int:category_id>/items'"""

    def get_template_name(self):
        return("items.html")

    def get_context(self, category_id):
        context = {
            "user": self.login_session,
            "error": False,
            "redirect_to_main": False
        }
        try:
            categories = self.session.query(Category).all()
            category = self.session.query(
                Category).filter_by(id=category_id).one()
            movies = category.movies
            context["categories"] = categories
            context["category"] = category
            context["movies"] = movies
        except Exception as e:
            context["error"] = True
            context["msg"] = e
        return context


class ItemView(TemplateView):
    """Handles GET request for '/catalog/item/<int:item_id>'"""

    def get_template_name(self):
        return("item.html")

    def get_context(self, item_id):
        context = {
            "user": self.login_session,
            "error": False,
            "redirect_to_main": False
        }
        try:
            movie = self.session.query(Movie).filter_by(id=item_id).one()
            context["movie"] = movie
        except Exception as e:
            context["error"] = True
            context["msg"] = e
        return context


class UserItemsView(TemplateView):
    """Handles GET request for '/catalog/user/<int:user_id>/items'"""

    def get_template_name(self):
        return "user_items.html"

    def get_context(self, user_id):
        context = {
            "user": self.login_session,
            "error": False,
            "redirect_to_main": False
        }
        try:
            if user_id == self.login_session["user_id"]:
                user_data = self.session.query(
                    User).filter_by(id=user_id).one()
                categories = self.session.query(Category).all()
                context["user_data"] = user_data
                context["categories"] = categories
            else:
                context["redirect_to_main"] = True
        except Exception as e:
            context["error"] = True
            context["msg"] = e
        return context


class CreateItemView(MethodView):
    """Handles GET, POST request
     for '/catalog/category/<int:category_id>/create'"""

    def __init__(self, session, login_session):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
        """
        self.session = session
        self.login_session = login_session
        self.form = CreateForm()

    def get(self, category_id):
        context = {
            "user": self.login_session,
            "error": False
        }
        if self.login_session.get("user_id"):
            try:
                category = self.session.query(
                    Category).filter_by(id=category_id).one()
                pre_select_category = category.name
                self.form.categories.data = [pre_select_category]
                context["category_id"] = category_id
                context["form"] = self.form
            except Exception as e:
                context["error"] = True
                context["msg"] = e
                return render_template("error.html", context=context)
            return render_template("create.html", context=context)
        else:
            return redirect(url_for("mainView"))

    def post(self, category_id):
        if self.login_session.get("user_id"):
            if self.form.validate():
                createMovie(self.form, self.session, self.login_session)
                return redirect(
                    url_for("CategoryView", category_id=category_id))
            else:
                return self.get(category_id)
        else:
            response = make_response(
                json.dumps("Unauthorized access denied."),
                401
            )
            response.headers["Content-Type"] = "application/json"
            return response


class EditItemView(MethodView):
    """Handles GET, POST request
     for '/catalog/item/<int:item_id>/edit'"""

    def __init__(self, session, login_session):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
        """
        self.session = session
        self.login_session = login_session
        self.form = CreateForm()

    def pre_fill_form(self, item):
        categories = list(map(
            lambda x: x.name, item.categories))
        self.form.title.data = item.name
        self.form.description.data = item.description
        self.form.poster.data = item.poster
        self.form.trailer.data = item.trailer
        self.form.categories.data = categories
        return True

    def get(self, item_id):
        context = {
            "user": self.login_session,
            "error": False
        }
        try:
            item = self.session.query(Movie).filter_by(id=item_id).one()
            if self.login_session.get("user_id") == item.user_id:
                self.pre_fill_form(item)
                context["item"] = item
                context["form"] = self.form
                return render_template("edit.html", context=context)
            else:
                return redirect(url_for("mainView"))
        except Exception as e:
            context["error"] = True
            context["msg"] = e
            return render_template("error.html", context=context)

    def post(self, item_id):
        context = {
            "user": self.login_session,
            "error": False
        }
        try:
            item = self.session.query(Movie).filter_by(
                id=item_id).one()
            if self.login_session.get("user_id") == item.user_id:
                if self.form.validate():
                    editMovie(self.form, self.session, item)
                    return redirect(url_for("ItemView", item_id=item_id))
                else:
                    return self.get(item_id)
            else:
                response = make_response(
                    json.dumps("Unauthorized access denied."),
                    401
                )
                response.headers["Content-Type"] = "application/json"
                return response
        except Exception as e:
            context["error"] = True
            context["msg"] = e
            return render_template("error.html", context=context)


class DeleteItemView(MethodView):
    """Handles GET, POST request
     for '/catalog/item/<int:item_id>/delete'"""

    def __init__(self, session, login_session):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
        """
        self.session = session
        self.login_session = login_session

    def get(self, item_id):
        context = {
            "user": self.login_session,
            "error": False
        }
        try:
            item = self.session.query(Movie).filter_by(id=item_id).one()
            if self.login_session.get("user_id") == item.user_id:
                context["item"] = item
                return render_template("delete.html", context=context)
            else:
                return redirect(url_for("mainView"))
        except Exception as e:
            context["error"] = True
            context["msg"] = e
            return render_template("error.html", context=context)

    def post(self, item_id):
        context = {
            "user": self.login_session,
            "error": False
        }
        try:
            item = self.session.query(Movie).filter_by(id=item_id).one()
            if self.login_session.get("user_id") == item.user_id:
                self.session.delete(item)
                self.session.commit()
                return redirect(url_for(
                    "UserItemsView",
                    user_id=self.login_session["user_id"]))
            else:
                response = make_response(
                    json.dumps("Unauthorized access denied."),
                    401
                )
                response.headers["Content-Type"] = "application/json"
                return response
        except Exception as e:
            context["error"] = True
            context["msg"] = e
            return render_template("error.html", context=context)


class ApiView(TemplateView):
    """Handles GET request
     for '/catalog/api/<int:user_id>'"""

    def get_template_name(self):
        return "api.html"

    def get_context(self, user_id):
        context = {
            "user": self.login_session,
            "error": False,
            "redirect_to_main": False
        }
        try:
            if user_id and user_id == self.login_session.get("user_id"):
                pass
            else:
                context["redirect_to_main"] = True
        except Exception as e:
            context["error"] = True
            context["msg"] = e
        return context


class UserProfileView(ApiView):
    """Handles GET request
     for '/user/<int:user_id>/profile'"""

    def get_template_name(self):
        return "user_profile.html"


class GenerateToken(MethodView):
    """Handles GET request
     for '/user/<int:user_id>/token', generates API token"""

    def __init__(self, session, login_session):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
        """
        self.session = session
        self.login_session = login_session

    def get(self, user_id):
        context = {
            "user": self.login_session,
            "error": False,
            "redirect_to_main": False
        }
        try:
            if user_id and user_id == self.login_session.get("user_id"):
                user = self.session.query(User).filter_by(id=user_id).one()
                token = user.generate_auth_token()
                self.login_session["API_TOKEN"] = token
                return redirect(url_for("UserProfileView", user_id=user_id))
            else:
                return redirect(url_for("mainView"))
        except Exception as e:
            context["error"] = True
            context["msg"] = e
            return render_template("error.html", context=context)


# --------------------------API--------------------------------------


class UserApi(MethodView):
    """Handles GET, DELETE requests
     for '/api/user/<string:email>'"""

    def __init__(self, session, login_session):
        """
            Args:
                session: sqlalchemy session object.
                login_session: flask session object.
        """
        self.session = session
        self.login_session = login_session

    def get(self, email):
        try:
            user = self.session.query(User).filter_by(email=email).one()
            return jsonify({"user_data": {
                "user": user.serialize
            }})
        except NoResultFound:
            return jsonify({"msg": "User was not found"})
        except Exception:
            return jsonify({"msg": "That's an error"})

    def delete(self, email):
        try:
            user = self.session.query(User).filter_by(email=email).one()
            self.session.delete(user)
            self.session.commit()
        except Exception as e:
            response = make_response(
                json.dumps({"error": e}),
                401
            )
            response.headers["Content-Type"] = "application/json"
            return response
        return jsonify({"msg": "User successfully deleted."})


class CatalogApi(MethodView):
    """Handles GET request
     for '/api/catalog' and '/api/catalog/<string:category_name>'"""

    def __init__(self, session):
        """
            Args:
                session: sqlalchemy session object.
        """
        self.session = session

    def get(self, category_name):
        try:
            if category_name:
                if category_name == "sci-fi":
                    category = self.session.query(Category).filter_by(
                    name="Sci-Fi").one()
                else:
                    category = self.session.query(Category).filter_by(
                        name=category_name.capitalize()).one()
                return jsonify({"category_data": category.serialize})
            else:
                movies = self.session.query(Movie).all()
                formated_movies = list(map(
                    lambda x: x.serialize, movies))
                return jsonify({"all_movies": formated_movies})
        except NoResultFound:
            return jsonify({"msg": "Category was not found"})
        except Exception:
            return jsonify({"msg": "That's an error"})


class ItemApi(MethodView):
    """Handles GET, POST, PUT, DELETE requests
     for '/api/catalog/item', '/api/catalog/item/<int:item_id>'"""

    def __init__(self, session):
        self.session = session
        """
            Args:
                session: sqlalchemy session object.
        """

    def get(self, item_id):
        try:
            item = self.session.query(Movie).filter_by(id=item_id).one()
            return jsonify(
                {"movie_data": item.serialize})
        except NoResultFound:
            return jsonify({"msg": "Movie was not found"})
        except Exception:
            return jsonify({"msg": "That's an error"})

    def post(self, item_id):
        try:
            data = json.loads(request.data)
            creation = createMovie(data, self.session, {"user_id": 1})
            if creation is True:
                return jsonify({
                    "msg": "Record created."
                })
            else:
                return jsonify({"error": str(creation)})

        except Exception as e:
            return jsonify({"msg": "That's an error"})

    def put(self, item_id):
        try:
            data = json.loads(request.data)
            item = self.session.query(Movie).filter_by(id=item_id).one()
            item_edit = editMovie(data, self.session, item)
            if item_edit is True:
                return jsonify({"msg": "Record successfully edited."})
            else:
                return jsonify({"error": str(item_edit)})
        except NoResultFound:
            return jsonify({"msg": "Movie was not found"})
        except Exception as e:
            print(e)
            return jsonify({"msg": "That's an error"})

    def delete(self, item_id):
        try:
            item = self.session.query(Movie).filter_by(id=item_id).one()
            item_name = item.name
            self.session.delete(item)
            self.session.commit()
            return jsonify(
                {"msg": "Movie '{}' was deleted.".format(item_name)})
        except NoResultFound:
            return jsonify({"msg": "Movie was not found"})
        except Exception:
            return jsonify({"msg": "That's an error"})
