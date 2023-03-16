# ChatGPT Web Interface

This project demonstrates how to create a web interface for ChatGPT using Flask, Gradio, and Google OAuth2 authentication. Users can log in using email/password or Google authentication. The application also implements a simple rate-limiting mechanism to limit the number of API requests per user within a specific time window.

## Requirements

To install the required packages, run:

```
pip install -r requirements.txt
```

## Setup

1. Replace the placeholders in the `chatgpt_webui.py` file with your own API credentials and secret keys:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `SECRET_KEY`
- `OPENAI_API_KEY`

2. Set up a Google OAuth2 project and obtain your `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` by following the instructions provided in this [answer](https://www.gitmemory.com/ChatGPT?topic=flask&category=8&question=38&answer=39).

## Running the Application

To run the application, simply execute the following command:

```
python chatgpt_webui.py
```

The web interface will be available at `http://localhost:5000/`.

## Notes

- This example uses an in-memory dictionary for rate-limiting, which may not be suitable for production environments. For a more robust solution, consider using a database to store user request counts and timestamps, as well as more advanced rate-limiting strategies or third-party libraries like Flask-Limiter.

- Always keep your API keys and secret keys safe, and do not share them publicly or commit them to version control systems.

- This project utilizes OpenAI's ChatGPT, an advanced AI language model. More information about ChatGPT can be found at https://platform.openai.com/docs/guides/chat/completion.
