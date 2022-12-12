import secrets, os
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, session, current_app
from spectrum import app, bcrypt, db, mail
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import extract
from functools import wraps
from datetime import datetime, date
from dateutil.relativedelta import *
import plotly, json
import plotly.graph_objs as go
import pandas as pd
import numpy as np
from flask_mail import Message
from spectrum.forms import LoginForm


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next = request.args.get('next')
            return redirect(next) if next else redirect(url_for('home'))

        else:
            flash(f'Login Unsuccessful. Please check email and password', 'danger')


    return render_template('login.html', title='Login',form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hash_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = Users(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data, email=form.email.data, password=hash_pw)
        db.session.add(user)
        db.session.commit()
        flash(f'Account has been created, you can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', 
                    sender='Spectrum_Support@gmail.com',
                    recipients=[user.email])

    msg.body = f'''To reset your Spectrum account password, click the following link: 
                {url_for('reset_token', token=token, _external=True)}
                If you did not make this request, please ignore this email'''
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('A reset password email has been sent.')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or expired token.', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hash_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        user.password = hash_pw
        db.session.commit()
        flash(f'Account has been created, you can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html',title='Reset Password' ,form=form)


#-------------------------- user page -----------------------#

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', title='Home')
    
@app.route('/about')
def about():
    
    return render_template('about.html', title='About')

@app.route('/product')
def product():
    
    return render_template('product.html', title='Product')


@app.route('/contact')
def contact():
    
    return render_template('contact.html', title='ContactUs')



