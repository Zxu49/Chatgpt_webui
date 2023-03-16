import os
import time
import gradio as gr
import openai
from flask import Flask, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_oauthlib.client import OAuth

# Replace these with your own credentials
GOOGLE_CLIENT_ID = 'your_google_client_id'
GOOGLE_CLIENT_SECRET = 'your_google_client_secret'
SECRET_KEY = 'your_secret_key'
OPENAI_API_KEY = 'your_openai_api_key'

openai.api_key = OPENAI_API_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
oauth = OAuth(app)
login_manager = LoginManager(app)

google = oauth.remote_app(
    'google',
    consumer_key=GOOGLE_CLIENT_ID,
    consumer_secret=GOOGLE_CLIENT_SECRET,
    request_token_params={
        'scope': 'email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login")
def login():
    return '''
        <form action="/auth/password" method="post">
            Email: <input type="text" name="email">
            Password: <input type="password" name="password">
            <input type="submit" value="Submit">
        </form>
        <a href="/auth/google">Login with Google</a>
    '''

@app.route("/auth/password", methods=["POST"])
def auth_password():
    email = request.form["email"]
    password = request.form["password"]

    # Replace this with your own user authentication logic
    if email == "user@example.com" and password == "password":
        user = User(email)
        login_user(user)
        return redirect(url_for("chatgpt"))
    else:
        return "Invalid email or password."

@app.route("/auth/google")
def auth_google():
    callback = url_for("authorized", _external=True)
    return google.authorize(callback=callback)

@app.route("/auth/google/callback")
@google.authorized_handler
def authorized(resp):
    if resp is None:
        return "Access denied."

    user = User(resp["email"])
    login_user(user)
    return redirect(url_for("chatgpt"))

@google.tokengetter
def get_google_oauth_token():
    return None

# Rate-limiting and ChatGPT API code

REQUEST_LIMIT = 10  # Limit the number of requests per user
TIME_WINDOW = 60 * 60  # Time window for rate limiting (1 hour, in seconds)

user_request_count = {}  # A simple in-memory dictionary to keep track of request count per user

@app.route("/chatgpt")
@login_required
def chatgpt():
    def chat_gpt_api(prompt):
        user_id = current_user.get_id()

        if user_id not in user_request_count:
            user_request_count[user_id] = {"count": 0, "timestamp": time.time()}

        if time.time() - user_request_count[user_id]["timestamp"] > TIME_WINDOW:
            user_request_count[user_id] = {"count": 1, "timestamp": time.time()}
        elif user_request_count[user_id]["count"] < REQUEST_LIMIT:
            user_request_count[user_id]["count"] += 1
        else:
            return "Request limit exceeded. Please wait before making more requests."

        response = openai.Completion.create(
            engine="text-davinci-002",
            prompt=prompt,
            max_tokens=50,
            n=1,
            stop=None,
            temperature=0.8,
        )
        return response.choices[0].text.strip()

    iface = gr.Interface(fn=chat_gpt_api, inputs="text", outputs="text", title="ChatGPT")
    return iface.serve_files()

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
