# Photo gallery system

A Flask-based photo gallery application that allows users to register, log in, and upload images to their own personal gallery.
Includes secure authentication, per-user storage, and a simple, clean interface.

## Features

~ User Authentication (Flask-Login + bcrypt hashing)

~ Unique user accounts (username cannot repeat)

~Per-user photo gallery

~ Automatic user folder creation

~ Image upload system

~ Password hashing with bcrypt

~ SQLite database (user_data.db)

~ Simple, clean UI with multiple views

## Installation
### clone
git clone https://github.com/chanchunkiu/user_photogallery.git
cd user_photogallery

### virtual environment
python3 -m venv venv
source venv/bin/activate      # Mac / Linux
venv\Scripts\activate         # Windows

### install libraries
pip install -r requirements.txt

## Run the application
1. python app.py
2. http://127.0.0.1:5000/ #run on browser

## structure of project
user_photogallery/
│
├── app.py
├── user_data.db
├── static/
│   └── uploads/             # User folders created automatically
├── templates/
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── index.html
│   └── …
└── README.md

## Security
1. This project uses Flask login session management
2. bycrypt for secure password hashing
3. SQLAlchemy for the User model

Passwords are hashed, not encrypted, which means even database is leaked, passwords would not be exposed.
<img width="680" height="246" alt="image" src="https://github.com/user-attachments/assets/b2f80d8d-5e6b-45f5-977e-38ecf307300c" />



Database leaks do not expose real passwords
## The home page 
Users can navigate between pages on the navigation bar
![image](https://github.com/user-attachments/assets/9669b01f-bd78-4248-8a42-f6b521b2b1e1)

## the login page
Users can log in with their username and password
![image](https://github.com/user-attachments/assets/7b658715-e2ab-4ce5-b968-5a5cb36d4856)

## the registration page
New users can sign up to use the photo hosting service 
![image](https://github.com/user-attachments/assets/14f7d7dc-efab-4eb4-a62f-a3e48a83a940)

## users' photo profile
after login, the website will greet the users and also show the currently uploaded photos in the gallery. 
There is also a browse and upload button to upload more photos to the gallery.
![image](https://github.com/user-attachments/assets/6256e814-3f49-4e07-a036-d9c56968e504)


