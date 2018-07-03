# Item-Catalog-App project

an application that provides a list of items ( this case - movies ) within a variety of categories  as well as provide a user registration and authentication system. Registered users have the ability to post, edit and delete their own items.

## Prerequisites

* Download [Python 2.7.15](https://www.python.org/downloads/) and install.

* Install virtualenv. It is a tool to create isolated Python environments. It creates an environment that has its own installation directories, that doesn’t share libraries with other virtualenv environments (and optionally doesn’t access the globally installed libraries either). This way you keep your system clean.

```bash
pip install virtualenv
```

* This app uses Google OAuth 2.0 client IDs authentication. You will need OAuth credentials. [Detail explanation](https://support.google.com/googleapi/answer/6158849?hl=en&ref_topic=7013279), how to obtain them. Download the client secret as a JSON data file and rename it to "client_secret.json".

## Usage

Clone repo from [Github.com](https://github.com/Tylenis/Item-Catalog-App.git):

```bash

git clone https://github.com/Tylenis/Item-Catalog-App.git
```

Navigate to **Item_Catalog_App** folder:

```bash
cd Item_Catalog_App
```

Create virtual environment:

```bash
virtualenv ENV
```

Install dependencies:

```bash
pip -r install requirements.txt
```

Copy **client_secret.json** file to **Item_Catalog_App** folder.

Run app:

```bash
python server.py
```

Open app in browser:

```bash
http://localhost:8000
```
