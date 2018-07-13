import json

from flask import Flask, g
from flask import session as login_session

from flask_sqlalchemy_session import flask_scoped_session
from flask_httpauth import HTTPTokenAuth

from config import Config
from models import Session, User
from routes import (
    MainView, CategoryView, ItemView, CreateItemView,
    UserItemsView, EditItemView, DeleteItemView,
    GoogleLogout, LoginView, GoogleLogin, ApiView, DeleteAccount,
    UserApi, CatalogApi, ItemApi, UserProfileView, GenerateToken)

app = Flask(__name__)

session = flask_scoped_session(Session, app)

auth = HTTPTokenAuth()


@auth.verify_token
def verify_token(token):
    """Chek if api user have valid authentication token.

        Args:
            token: authentication token.
    """

    user_id = User.verify_auth_token(token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        return False
    g.user = user
    return True


# -------------Custom Filters------------------------------------


@app.template_filter()
def toTitle(text):
    return text.title()

# -------------ROUTES: Authentication------------------------------------

CLIENT_SECRET_FILE = "client_secret.json"
CLIENT_ID = json.loads(
    open(CLIENT_SECRET_FILE, "r").read())["web"]["client_id"]


app.add_url_rule("/catalog/login", view_func=LoginView.as_view(
    "LoginView", session, login_session, client_id=CLIENT_ID)
)


app.add_url_rule("/catalog/googlelogin", view_func=GoogleLogin.as_view(
    "GoogleLogin", session, login_session, CLIENT_SECRET_FILE, CLIENT_ID)
)

app.add_url_rule("/catalog/googlelogout", view_func=GoogleLogout.as_view(
    "GoogleLogout", login_session, auth_required=True)
)

app.add_url_rule(
    "/user/<int:user_id>/delete_account", view_func=DeleteAccount.as_view(
        "DeleteAccount", login_session, session
    ))

# -------------ROUTES: API-----------------------------------------------


user_api = auth.login_required(UserApi.as_view(
    "UserApi", session, login_session))
catalog_api = auth.login_required(CatalogApi.as_view("CatalogApi", session))
item_api = auth.login_required(ItemApi.as_view("ItemApi", session))

app.add_url_rule(
    "/api/user/<string:email>", view_func=user_api,
    methods=["GET", ]
)

app.add_url_rule(
    "/api/user/<string:email>", view_func=user_api, methods=["DELETE", ]
)

app.add_url_rule(
    "/api/catalog", defaults={"category_name": None},
    view_func=catalog_api, methods=["GET", ]
)

app.add_url_rule(
    "/api/catalog/<string:category_name>",
    view_func=catalog_api, methods=["GET", ]
)

app.add_url_rule(
    "/api/catalog/item", view_func=item_api, defaults={"item_id": None},
    methods=["POST", ]
)

app.add_url_rule(
    "/api/catalog/item/<int:item_id>", view_func=item_api,
    methods=["GET", ]
)

app.add_url_rule(
    "/api/catalog/item/<int:item_id>", view_func=item_api,
    methods=["PUT", ]
)

app.add_url_rule(
    "/api/catalog/item/<int:item_id>", view_func=item_api,
    methods=["DELETE", ]
)

# -------------ROUTES: CRUD----------------------------------------------


app.add_url_rule("/", view_func=MainView.as_view(
    "mainView", session, login_session, client_id=CLIENT_ID)
)


app.add_url_rule(
    "/catalog/category/<int:category_id>/items",
    view_func=CategoryView.as_view(
        "CategoryView", session, login_session, client_id=CLIENT_ID)
)


app.add_url_rule(
    "/catalog/item/<int:item_id>",
    view_func=ItemView.as_view(
        "ItemView", session, login_session, client_id=CLIENT_ID)
)


app.add_url_rule(
    "/catalog/category/<int:category_id>/create",
    view_func=CreateItemView.as_view(
        "CreateItemView", session, login_session, client_id=CLIENT_ID)
)


app.add_url_rule(
    "/catalog/user/<int:user_id>/items",
    view_func=UserItemsView.as_view(
        "UserItemsView", session, login_session, auth_required=True, client_id=CLIENT_ID)
)


app.add_url_rule(
    "/catalog/item/<int:item_id>/edit",
    view_func=EditItemView.as_view(
        "EditItemView", session, login_session, client_id=CLIENT_ID)
)


app.add_url_rule(
    "/catalog/item/<int:item_id>/delete",
    view_func=DeleteItemView.as_view(
        "DeleteItemView", session, login_session, client_id=CLIENT_ID)
)


app.add_url_rule(
    "/catalog/api/<int:user_id>", view_func=ApiView.as_view(
        "ApiView", session, login_session, client_id=CLIENT_ID)
)

app.add_url_rule(
    "/user/<int:user_id>/profile", view_func=UserProfileView.as_view(
        "UserProfileView", session, login_session, client_id=CLIENT_ID)
)

app.add_url_rule(
    "/user/<int:user_id>/token", view_func=GenerateToken.as_view(
        "GenerateToken", session, login_session
    )
)


if __name__ == "__main__":
    app.debug = True
    app.config.from_object(Config)
    app.run(host="0.0.0.0", port=Config.PORT)
