# user_management
This is a sample repo for sms and email verification


# Installation

1. Git clone this repo
1. You might need to install redis server and start redis
    1. sudo apt-get install redis-server
    1. sudo service redis-server start
1. Install all the requirements in the virtualenv of your choice
    1. pip install -r requirements.txt
1. Migrate the app
    1. ./manage.py makemigrations
    1.  ./ manage.py migrate
    
For production setup, you might need to add the server's ip address in ALLOWED_HOSTS in settings/base.py

You will also need to update base.py to set email credentials for sending mails. Set smtp ports, from email and password in base.py

Start celery server in new terminal, run
```sh
celery -A user_management worker -l info
```

After setting up all the dependencies, you can start the server
```sh
./manage.py runserver 127.0.0.1:8000
```
And visit http://127.0.0.1:8000

I have used twilio to send sms, which is on a trial period.
