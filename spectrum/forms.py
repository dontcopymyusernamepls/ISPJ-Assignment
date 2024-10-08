from logging import PlaceHolder
from operator import length_hint
from unittest.util import _MAX_LENGTH
from flask_login.mixins import UserMixin
from wtforms import StringField, SubmitField, PasswordField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp
from spectrum.database import Users, User, Staff, Addproducts, Category
from flask_login import current_user
from wtforms import SubmitField, IntegerField, FloatField, StringField, TextAreaField, validators, SelectField, BooleanField
from flask_wtf.file import FileField, FileRequired, FileAllowed
import onetimepass
import pyqrcode


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username =  StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password',validators=[DataRequired(), Regexp('^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z]).{8,20}$', message='Password must contain 1 uppercase and lowercase letter, 1 special character [!@#$&*], at least 2 numerical and at least 8 characters.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = Users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is taken.')

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is taken.')
    

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    token = StringField('Token', validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField('Login')

class UpdateUserAccountForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    username =  StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = Users.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username is taken.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = Users.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('email is taken.')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')
    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError(f'There is no account named {email.data}.')

class ResetPasswordForm(FlaskForm):
    password = StringField('Password', validators=[DataRequired()])
    confirm_password = StringField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class AddproductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    category = SelectField('Category', validators=[DataRequired()], choices=[('New Arrival'), ('Most Popular'), ('Limited Time'), ('Top'), ('Bottom'), ('Socks'), ( 'Shoes'), ( 'Equipments'), ('Accessories'), ('Others')])
    # category = SelectField('Category', validators=[DataRequired()], choices=[(1, 'New Arrival'), (2, 'Most Popular'), (3, '	Limited Time'), (4, 'Top'), (5, 'Bottom'), (6, 'Socks'), (7, 'Shoes'), (8, 'Equipments'), (9, 'Accessories'), (10, 'Others')])
    price = FloatField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    length = IntegerField('Length', validators=[DataRequired()])
    width = IntegerField('Width', validators=[DataRequired()])
    depth = IntegerField('Depth', validators=[DataRequired()])
    image_1 = FileField('Cover Image', validators=[FileRequired(), FileAllowed(['jpg','png','gif','jpeg'])])
    image_2 = FileField('Image 2', validators=[ FileAllowed(['jpg','png','gif','jpeg'])])
    image_3 = FileField('Image 3', validators=[ FileAllowed(['jpg','png','gif','jpeg'])])
    image_4 = FileField('Image 4', validators=[FileAllowed(['jpg','png','gif','jpeg'])])
    image_5 = FileField('Image 5', validators=[ FileAllowed(['jpg','png','gif','jpeg'])])
    submit = SubmitField("Add product")


class UpdateProductForm(FlaskForm):
    name = StringField('Product Name', [validators.DataRequired()])
    description = TextAreaField('Description', [validators.DataRequired()])
    category = SelectField('Category', validators=[DataRequired()], choices=[('New Arrival'), ('Most Popular'), ('Limited Time'), ('Top'), ('Bottom'), ('Socks'), ( 'Shoes'), ( 'Equipments'), ('Accessories'), ('Others')])
    price = FloatField('Price', [validators.DataRequired()])
    stock = IntegerField('Stock', [validators.DataRequired()])
    length = IntegerField('Length', [validators.DataRequired()])
    width = IntegerField('Width', [validators.DataRequired()])
    depth = IntegerField('Depth', [validators.DataRequired()])
    image_1 = FileField('Cover Image', validators=[FileAllowed(['jpg','png','gif','jpeg'])])
    image_2 = FileField('Image 2', validators=[FileAllowed(['jpg','png','gif','jpeg'])])
    image_3 = FileField('Image 3', validators=[FileAllowed(['jpg','png','gif','jpeg'])])
    image_4 = FileField('Image 4', validators=[FileAllowed(['jpg','png','gif','jpeg'])])
    image_5 = FileField('Image 5', validators=[FileAllowed(['jpg','png','gif','jpeg'])])
    submit = SubmitField("Update Product")

class AdminRegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email  = StringField('Email',validators=[DataRequired(), Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('email is taken.')


class AddToCartForm(FlaskForm):
    submit = SubmitField("Add To Cart")

class AddReviewForm(FlaskForm):
    review = TextAreaField('Review', validators=[DataRequired(), Length(min=10, max=1000)])
    rating = SelectField('Product Rating', choices=[(1, '1 Star'), (2, '2 Star'), (3, '3 Star'), (4, '4 Star'), (5, '5 Star')])
    submit = SubmitField('Submit')

class CheckOutForm(FlaskForm):
    full_name =  StringField('Full Name', validators=[DataRequired()])
    address = TextAreaField('Address', validators=[DataRequired()])
    postal_code = StringField('Postal Code', validators=[DataRequired()])
    card_number = StringField('Card Number', validators=[DataRequired()], render_kw={"PlaceHolder": "•••• •••• •••• ••••"})
    expiry = StringField('Expiry', validators=[DataRequired()], render_kw={"PlaceHolder": "MM/YY"})
    cvv = StringField('CVV', validators=[DataRequired()], render_kw={"PlaceHolder": "•••"})
    submit = SubmitField('Checkout')

class VerifyCheckOutForm(FlaskForm):
    Otp_number = StringField('OTP Number', validators=[DataRequired()], render_kw={"PlaceHolder": "••••"})
    submit = SubmitField('Verify')

class Feedback(FlaskForm):
    full_name = StringField('Full name', validators=[DataRequired(),Length(min=3, max=26)], render_kw={"PlaceHolder": "Amy Tan"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"PlaceHolder": "AmyTan@gmail.com"})
    phone_number = StringField('Phone Number', validators=[DataRequired(),Length(min=8, max=11)], render_kw={"PlaceHolder": "+65 12345678"})
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')