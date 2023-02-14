import secrets, os
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, session, current_app, jsonify
from spectrum import app, bcrypt, db, mail, users_logger, error_logger, admin_logger, product_logger, root_logger
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import extract
from functools import wraps
from datetime import datetime, date
from dateutil.relativedelta import *
import plotly, json, random
import plotly.graph_objs as go
import pandas as pd
import numpy as np
from flask_mail import Message
from spectrum.forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm, UpdateUserAccountForm, AddproductForm, UpdateProductForm, AdminRegisterForm, AddToCartForm, AddReviewForm, CheckOutForm, VerifyCheckOutForm, Feedback
from spectrum.database import Staff, Users, User, Addproducts, Category, Items_In_Cart, Review, Customer_Payments, Product_Bought, Feedbackform, PassKeyDevice
import spectrum.MyCaesarcipher as cipher
import spectrum.rsa as rsa
import spectrum.salting as salt
from io import BytesIO
import onetimepass
import pyqrcode
import re

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
    generate_authentication_options,
    verify_authentication_response
)

from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    RegistrationCredential,
    UserVerificationRequirement,
    AuthenticationCredential
)


def trunc_datetime(someDate):
    return someDate.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.role == "admin":
            return f(*args, **kwargs)
        else:
            abort(401)
    return wrap

#--------------------CUSTOM-ERROR-PAGE-------------------------#

@app.errorhandler(401)
def unauthorized(e):
    return render_template('error/401.html'), 401

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('error/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 500 status explicitly
    return render_template('error/500.html'), 500

#--------------------PASSKEYS-USER-AUTHENTICATION--------------------------#

@app.route('/generate_authentication_options', methods=['GET'])
def generate_authentication_options_route():
    email = request.args.get("email")

    print(email, type(email))
    if email == "":
        flash("Email cannot be blank for Passkeys Login")
        return "", 400

    user = User.query.filter_by(email=email).first()
    devices = PassKeyDevice.query.filter_by(uid=user.id)

    if user is None:
        flash(f'Oops! Login unsuccessful. Please check your details.', 'danger')
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        users_logger.info('%s - - [%s] REQUEST[%s] %s encountered unsuccessful login.', request.remote_addr, dt, request.method, email)
        return redirect(url_for('login'))

    # challenge
    challenge = os.urandom(8)

    # specify how passkey is to be generated
    options = generate_authentication_options(
        rp_id="localhost",
        challenge=challenge,
        timeout=60000,
        allow_credentials=list(map(lambda x : PublicKeyCredentialDescriptor(id=x.credentialID), devices)),
        user_verification=UserVerificationRequirement.REQUIRED
    )

    session["pk_challenge"] = challenge

    return options_to_json(options)

#checks if fingerprint is valid
@app.route('/verify_authentication', methods=['POST'])
def verify_authentication():
    data = request.get_data()
    dataJSON = request.json

    email = dataJSON["email"]

    if email is None:
        flash("Email cannot be blank for Passkeys Login")
        return

    user = User.query.filter_by(email=email).first()
    devices = PassKeyDevice.query.filter_by(uid=user.id)
    devAuth = None

    for dev in devices:
        if dev.credentialID == base64url_to_bytes(dataJSON["id"]):
            devAuth = dev
            break
    
    # error if fingerprint invalid
    if devAuth is None:
        return "This device is not registered with Passkeys.", 400

    auth_verification = verify_authentication_response(
        credential=AuthenticationCredential.parse_raw(data),
        expected_challenge=session["pk_challenge"],
        expected_origin="https://localhost:8443",
        expected_rp_id="localhost",
        require_user_verification=True,
        credential_public_key=devAuth.credentialPublicKey,
        credential_current_sign_count=0
    )

    print(auth_verification)

    # if fingerprint valid, redirect to home page
    if request.method == "POST":
        # record the user name
        session["email"] = email
        if session.get('email'):
            flash("Welcome {}!".format(session.get('email')))
            
    # log user in
    login_user(user)
    dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    users_logger.info('%s - - [%s] REQUEST[%s] %s logged in successfully.', request.remote_addr, dt, request.method, email)
    flash('You are now logged in!')
    next = request.args.get('next')
    return url_for('home')

# add passkey to account
@app.route('/generate_registration_options', methods=['GET'])
def generate_registration_options_route():

    devices = PassKeyDevice.query.filter_by(uid=current_user.id)
    # challenge
    challenge = os.urandom(8)

    # specify how passkey is to be generated
    options = generate_registration_options(
        rp_id="localhost",
        rp_name="Spectrum App",
        user_id=str(current_user.id),
        user_name=current_user.username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
        ),

        # prevent multiple signups of passkey
        exclude_credentials=list(map(
            lambda x : PublicKeyCredentialDescriptor(id=bytes(x.credentialID)),
            devices
        )),
        timeout=60000,
        challenge=challenge
    )

    session["pk_challenge"] = challenge
    # sent back to account.html as data

    return options_to_json(options)

@app.route('/verify-registration', methods=['POST'])
def verify_registration():
    data = request.get_data()
    # add passkey
    reg_verification = verify_registration_response(
        credential=RegistrationCredential.parse_raw(data),
        expected_challenge=session["pk_challenge"],
        expected_origin="https://localhost:8443",
        expected_rp_id="localhost",
        require_user_verification=True
    )

    # create passkey in database
    dev = PassKeyDevice(
        credentialID=reg_verification.credential_id,
        credentialPublicKey=reg_verification.credential_public_key,
        uid=current_user.id
    )
    db.session.add(dev)
    db.session.commit()

    return ""

#--------------------LOGIN-LOGOUT-REGISTER-PAGE--------------------------#

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        
        # add new user to the database
        random_string = salt.generate_random()
        password_salt = salt.append_random(form.password.data, random_string)
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data, email=form.email.data, salt=random_string, password=password_salt)
        db.session.add(user)
        db.session.commit()
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        users_logger.info('%s - - [%s] REQUEST[%s] %s has created an account.', request.remote_addr, dt, request.method, form.email.data)

        # redirect to the two-factor auth page, passing username in session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)


@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('home'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('home'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        salt = user.salt
        password_salt = form.password.data + salt
        # something wrong with user.verify_totp it don't work
        if user is None or not user.verify_password(password_salt): #or \
                #not user.verify_totp(form.token.data):
                flash(f'Oops! Login unsuccessful. Please check your details.', 'danger')
                dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
                users_logger.info('%s - - [%s] REQUEST[%s] %s encountered unsuccessful login.', request.remote_addr, dt, request.method, form.email.data)
                return redirect(url_for('login'))
        
        if request.method == "POST":
            # record the user name
            session["email"] = request.form.get("email")
            if session.get('email'):
                flash("Welcome {}!".format(session.get('email')))
                
        # log user in
        login_user(user)
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        users_logger.info('%s - - [%s] REQUEST[%s] %s logged in successfully.', request.remote_addr, dt, request.method, form.email.data)
        flash('You are now logged in!')
        next = request.args.get('next')
        return redirect(next) if next else redirect(url_for('home'))
    return render_template('login.html', title='Login',form=form)


@app.route('/get_session')
def get_session():
    if not session.get("email"):
        return redirect("/login")
    return render_template('get_session.html')


@app.route('/logout')
def logout():
    dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    users_logger.info('%s - - [%s] REQUEST[%s] %s logged out.', request.remote_addr, dt, request.method, current_user.email) 
    logout_user()
    session["email"] = None
    flash('You are now logged out.')
    return redirect(url_for('home'))


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
        random_string = salt.generate_random()
        password_salt = salt.append_random(form.password.data, random_string)
        #hash_pw = bcrypt.generate_password_hash(password_salt).decode('utf-8')

        user.password = password_salt
        db.session.commit()
        flash(f'Account has been created, you can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html',title='Reset Password' ,form=form)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateUserAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data, current_user.image_file)
            current_user.image_file = picture_file
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated.', 'success')
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        users_logger.info('%s - - [%s] REQUEST[%s] %s has updated their account.', request.remote_addr, dt, request.method, form.email.data)
        return redirect(url_for('account'))

    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.username.data = current_user.username
        form.email.data = current_user.email

    image_file = url_for('static', filename='images/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form)

@app.route('/account/delete', methods=['POST'])
@login_required
def delete_account():
    user = User.query.filter_by(username=current_user.username).first()
    db.session.delete(user)
    db.session.commit()
    dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    users_logger.info('%s - - [%s] REQUEST[%s] %s deleted their account.', request.remote_addr, dt, request.method, current_user.email)
        
    flash('Your account has been deleted.', 'success')
    return redirect(url_for('home'))


#-------------------------- user page -----------------------#

@app.route('/')
@app.route('/home')
def home():
    products = Addproducts.query.all()

    return render_template('home.html', title='Home', products=products)
    
@app.route('/about')
def about():
    
    return render_template('about.html', title='About Us')

@app.route('/product')
def product():
    products = Addproducts.query.all()

    return render_template('product.html', title='Products', products=products)

@app.route('/search', methods=['GET'])
def search():
    keyword = request.args.get('query')
    products = Addproducts.query.msearch(keyword,fields=['name', 'description'])
    return render_template("product.html",title='Search ' + keyword, products=products)

@app.route('/contact')
def contact():
    
    return render_template('contact.html', title='Contact Us')

def save_picture(form_pic, current_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_pic.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_pic)
    i.thumbnail(output_size)
    i.save(picture_path)

    if current_picture != "defaultpfp.jpg":
        os.remove(os.path.join(app.root_path, "static/images/", current_picture))


    return picture_fn

# def MagerDicts(dict1,dict2):
#     if isinstance(dict1, list) and isinstance(dict2,list):
#         return dict1  + dict2
#     if isinstance(dict1, dict) and isinstance(dict2, dict):
#         return dict(list(dict1.items()) + list(dict2.items()))

@app.route('/addtocart', methods=['POST'])
def AddtoCart():
    try:
        products_id = request.form.get('product_id')
        quantity = int(request.form.get('quantity'))

        product = Addproducts.query.filter_by(id=products_id).all()[0]

        if request.method == "POST":
            DictItems = {products_id:{'name':product.name, 'image':product.image_1, 'price':product.price, 'quantity':quantity}}

            if 'shoppingcart' in session and session['shoppingcart'] is not None:

                print(session['shoppingcart'])
                if products_id in session['shoppingcart']:
                    for key, item in session['shoppingcart'].items():
                        if int(key) == int(products_id):
                            session.modified = True
                            item['quantity'] += quantity
                    
                else:
                    session['shoppingcart'] = session['shoppingcart'] | DictItems
                    flash(f"Added {quantity} {product.name} to cart!")
                    return redirect(request.referrer)

            else:
                session['shoppingcart'] = DictItems
                flash(f"Added {quantity} {product.name} to cart!")
                return redirect(request.referrer)

    except Exception as e:
        print(e)
    finally:
        flash(f"Added {quantity} to cart!")
        return redirect(request.referrer)


@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    if 'shoppingcart' not in session:
        session['shoppingcart'] = dict()
        #return redirect(request.referrer)

    subtotal = 0
    total = 0

    for key, product in session['shoppingcart'].items():
        subtotal += float(product['price']) * int(product['quantity'])
        total = float("%.2f" % (1 * subtotal))

    cart_items = Items_In_Cart.query.filter_by(user_id=current_user.id).all()
    items = 0
    for item in cart_items:
        items += 1
    return render_template('cart.html', title='Shopping Cart', current_user=current_user, cart_items=cart_items, items=items, total=total)

@app.route('/deleteitem/<int:id>')
def deleteitem(id):
    if 'shoppingcart' not in session:
        return redirect(url_for('home'))
    try:
        session.modified = True
        for key , item in session['shoppingcart'].items():
            if int(key) == id:
                session['shoppingcart'].pop(key, None)
                return redirect(request.referrer)
    except Exception as e:
        print(e)
        return redirect(request.referrer)



# Checkout  
@app.route('/checkout', methods=['POST', 'GET'])
@login_required
def checkout_details():
    form = CheckOutForm()
    cart_items = session["shoppingcart"] # Items_In_Cart.query.filter_by(user_id=current_user.id).all()
    subtotal = 0
    total = 0
    print(cart_items)
    for key, item in cart_items.items():
        print(item)
        product = Addproducts.query.filter_by(id=key).first()
        if product.stock < item['quantity']:
            flash('{{product.name}} only has {{product.stock}} left in stock', 'danger')
            return redirect(url_for('cart'))
        else:
            subtotal += item['price']
    
    total = subtotal + 10

    keysize = 2048
    private_keyfile = "a_private.pem"
    public_keyfile = "a_public.pem"
    
    private_key = rsa.read_private_key(private_keyfile)
    public_key = rsa.read_public_key(public_keyfile)

    if form.validate_on_submit():

        credit_card_number = form.card_number.data
        # supports only master and visa
        valid = re.search("^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$", credit_card_number)

        if valid is None:
            flash("Invalid Credit Card Number!")
            return render_template('checkout.html', title='Checkout',form=form, cart_items=cart_items, subtotal=subtotal, total=total)

        full_name = form.full_name.data
        en_address = rsa.encrypt(public_key, form.address.data.encode('utf-8'))
        postal_code = form.postal_code.data
        en_card_number = rsa.encrypt(public_key, form.card_number.data.encode('utf-8'))
        checkout_details = Customer_Payments(full_name=full_name, address=en_address, postal_code=postal_code, card_number=en_card_number)
        db.session.add(checkout_details)
        
        print(cart_items)
        for key, cart_item in cart_items.items():
            product = Addproducts.query.filter_by(id=key).first()
            product.stock = product.stock - cart_item["quantity"]
            product_bought = Product_Bought(quantity=cart_item["quantity"], product_id=key, user_id=current_user.id, product_name=cart_item["name"], image=cart_item["image"], price=cart_item["price"])
            db.session.add(product_bought)
            # db.session.delete(cart_item)
            session["shoppingcart"] = dict()
            db.session.commit()
        flash(f'Your order has been submitted!','success')
        return redirect(url_for('thanks')) #verify
    return render_template('checkout.html', title='Checkout',form=form, cart_items=cart_items, subtotal=subtotal, total=total)

#@app.route('/verify_checkout_page')
#def verify():
    form = VerifyCheckOutForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_totp(form.otp.data):
                flash(f'Oops! You have to verify your identity before you can proceed with the checkout.', 'danger')
                return redirect(url_for('verify'))

        login_user(user)
        flash('You have successfully verified your identity!')
        return render_template('verify', title = "Verify Identity")
#generateopt =random.randint(000000,100000)

          
@app.route('/thanks')
def thanks():
    return render_template('thanks.html', title='Order Confirmed')


@app.route('/product_details/<int:id>', methods=['GET', 'POST'])
def product_details(id):
    products = Addproducts.query.get_or_404(id)
    product_reviews = Review.query.filter_by(product_id=id)
    if current_user.is_authenticated:
        product_bought = Product_Bought.query.filter_by(user_id=current_user.id, product_id=id).first()
    else:
        product_bought = None
    form = AddReviewForm()
    if form.validate_on_submit():
        review = Review(user_review=form.review.data, product_id=id, author=current_user, rating=form.rating.data)
        db.session.add(review)
        db.session.commit()
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        product_logger.info('%s - - [%s] REQUEST[%s] %s Your review has been added.', request.remote_addr, dt, request.method, current_user.email)

        flash('Your review has been added!', 'success')
        return redirect(url_for('shop'))
    return render_template('product_details.html', title="Product Details", products=products, product_reviews=product_reviews ,form=form, product_bought=product_bought)

@app.route('/feedback', methods=['GET','POST'])
def Userfeedbackform():
    form = Feedback()
    # keysize = 2048
    # private_keyfile = "a_private.pem"
    # public_keyfile = "a_public.pem"
    
    # keypair = rsa.generate_keypair(keysize)
    
    # rsa.write_private_key(keypair, private_keyfile)
    # rsa.write_public_key(keypair, public_keyfile)
    
    # private_key = rsa.read_private_key(private_keyfile)
    # public_key = rsa.read_public_key(public_keyfile)
    # keysize = 2048
    private_keyfile = "a_private.pem"
    public_keyfile = "a_public.pem"


    # generate keypair
    # keypair = rsa.generate_keypair(keysize)

    # # store keypair in files
    # rsa.write_private_key(keypair, private_keyfile)
    # rsa.write_public_key(keypair, public_keyfile)

    # read keypair from files
    private_key = rsa.read_private_key(private_keyfile)
    public_key = rsa.read_public_key(public_keyfile)

    if form.validate_on_submit():
        full_name = form.full_name.data
        email_data = form.email.data
        phone_data = form.phone_number.data
        message_data = form.message.data
        email = rsa.encrypt(public_key, email_data.encode("utf8"))
        phone_number = rsa.encrypt(public_key, phone_data.encode("utf8"))
        message = rsa.encrypt(public_key, message_data.encode("utf8"))
        feedback = Feedbackform(full_name=full_name,email=email,phone_number=phone_number,message=message)
        db.session.add(feedback)
        db.session.commit()
        flash(f'Your feedback has been submitted!','success')
        return redirect(url_for('feedback_received'))

    # if form.validate_on_submit():
    #     full_name = form.full_name.data
    #     email = rsa.encrypt(public_key, form.email.data.encode('utf-8'))
    #     phone_number = rsa.encrypt(public_key,form.phone_number.data.encode('utf-8'))
    #     message = rsa.encrypt(public_key,form.message.data.encode('utf-8'))
    #     feedback = Feedbackform(full_name=full_name,email=email,phone_number=phone_number,message=message)
    #     db.session.add(feedback)
    #     db.session.commit()
    #     flash(f'Your feedback has been submitted!','success')
    #     return redirect(url_for('feedback_received'))
    return render_template('feedback.html',form=form)

@app.route('/feedbackreceived')
def feedback_received():
    return render_template('feedbackreceived.html',title = 'We hear you!')

#---------------------ADMIN-PAGE------------------------#

@app.route('/admin/register', methods=['GET', 'POST'])
@login_required
#admin_required
def admin_register():
    """User registration route."""
    #if current_user.is_authenticated:
        # if user is logged in we get out of here
        #return redirect(url_for('admin_register'))
    form = AdminRegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('admin_register'))
        # add new user to the database
        random_string = salt.generate_random()
        password_salt = salt.append_random(form.password.data, random_string)
        user = Staff(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data, email=form.email.data, salt=random_string, password=password_salt, role='admin')
        db.session.add(user)
        db.session.commit()
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        admin_logger.info('%s - - [%s] REQUEST[%s] %s has created an account.', request.remote_addr, dt, request.method, form.email.data)

        # redirect to the two-factor auth page, passing username in session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('admin/register.html', form=form)

@app.route('/admin/dashboard')
@login_required
@admin_required
def dashboard():
    dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    admin_logger.info('%s - - [%s] REQUEST[%s] %s accessed the dashboard.', request.remote_addr, dt, request.method, current_user.email)
    return render_template('/admin/dashboard.html', title='Dashboard')

def save_product_picture(form_pic):
    random_hex = secrets.token_hex(10)
    _, f_ext = os.path.splitext(form_pic.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)

    output_size = (945, 945)
    i = Image.open(form_pic)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route('/admin/add_product', methods=['POST', 'GET'])
@login_required 
@admin_required
def add_product():
    form = AddproductForm()
    categories = Category.query.all()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        length = form.length.data
        width = form.width.data
        depth = form.depth.data
        category = form.category.data
        price = form.price.data
        stock = form.stock.data
        print(category, "\n\n\n\n\n")
        image_1 = save_product_picture(form.image_1.data)
        image_2 = save_product_picture(form.image_1.data)
        image_3 = save_product_picture(form.image_1.data)
        image_4 = save_product_picture(form.image_1.data)
        image_5 = save_product_picture(form.image_1.data)
        add_product = Addproducts(name = name, description = description, length = length, width = width, depth = depth, category_id = category, price = price, stock = stock, image_1 = image_1, image_2 = image_2, image_3 = image_3, image_4 = image_4, image_5 = image_5)
        db.session.add(add_product)
        db.session.commit()
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        admin_logger.info('%s - - [%s] REQUEST[%s] %s added %s to the database!', request.remote_addr, dt, request.method, current_user.email, name)
        flash(f'The product {name} has been added to database!','success')
        return redirect(url_for('add_product'))
    return render_template('admin/add_product.html', form=form, title='Add a Product', categories=categories)


@app.route('/admin/display_product')
@login_required
@admin_required
def display_product():
    dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    admin_logger.info('%s - - [%s] REQUEST[%s] %s accessed the product list.', request.remote_addr, dt, request.method, current_user.email)
    products = Addproducts.query.all()
    return render_template('admin/display_product.html', title='Product List', products=products)


@app.route('/updateproduct/<int:id>', methods=['GET','POST'])
@login_required
@admin_required
def update_product(id):
    form = UpdateProductForm()
    product = Addproducts.query.get_or_404(id)
    categories = Category.query.all()
    category = form.category.data
    if form.validate_on_submit():
        product.name = form.name.data 
        product.description = form.description.data
        product.length = form.length.data
        product.width = form.width.data
        product.depth = form.depth.data
        product.price = form.price.data 
        product.stock = form.stock.data
        product.category_id = category
        
        if request.files.get('image_1'):
            try:
                os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_1))
                product.image_1 = save_product_picture(request.files.get('image_1'))
            except:
                product.image_1 = save_product_picture(request.files.get('image_1'))
        if request.files.get('image_2'):
            try:
                os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_2))
                product.image_2 = save_product_picture(request.files.get('image_2'))
            except:
                product.image_2 = save_product_picture(request.files.get('image_2'))
        if request.files.get('image_3'):
            try:
                os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_3))
                product.image_3 = save_product_picture(request.files.get('image_3'))
            except:
                product.image_3 = save_product_picture(request.files.get('image_3'))
        if request.files.get('image_4'):
            try:
                os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_3))
                product.image_4 = save_product_picture(request.files.get('image_4'))
            except:
                product.image_4 = save_product_picture(request.files.get('image_4'))
        if request.files.get('image_5'):
            try:
                os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_3))
                product.image_5 = save_product_picture(request.files.get('image_5'))
            except:
                product.image_5 = save_product_picture(request.files.get('image_5'))

        db.session.commit()
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        admin_logger.info('%s - - [%s] REQUEST[%s] %s updated a product.', request.remote_addr, dt, request.method, current_user.email, product.name)
        flash('The product has been updated!','success')
        return redirect(url_for('display_product'))
    form.name.data = product.name
    form.description.data = product.description
    form.length.data = product.length
    form.width.data = product.width
    form.depth.data = product.depth
    form.price.data = product.price
    form.stock.data = product.stock
    category = product.category_id

    return render_template('admin/add_product.html', form=form, title='Update Product',getproduct=product, categories=categories)

@app.route('/deleteproduct/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_product(id):
    product = Addproducts.query.get_or_404(id)
    if request.method =="POST":
        try:
            os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_1))
            os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_2))
            os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_3))
            os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_4))
            os.unlink(os.path.join(current_app.root_path, "static/images/" + product.image_5))
        except Exception as e:
            print(e)
        dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        admin_logger.info('%s - - [%s] REQUEST[%s] %s deleted %s from the product list. ', request.remote_addr, dt, request.method, current_user.email, product.name)
        db.session.delete(product)
        db.session.commit()
        flash(f'The product {product.name} has been deleted from the product list.','success')
        return redirect(url_for('display_product'))
    flash(f'Cannot delete the product.','success')
    return redirect(url_for('display_product'))

@app.route('/admin/customer_database')
@login_required
@admin_required
def customer_database():
    customers = User.query.filter_by(role='user').all()
    customer_list = []
    for customer in customers:
        first_name = customer.first_name
        last_name = customer.last_name
        email = customer.email
        username = customer.username
        customer.first_name = first_name.replace(first_name[1:4], "***", 1)
        customer.last_name = last_name.replace(last_name[1:4], "***", 1)
        at = email.rfind('@')
        number = (at-1)-1 
        customer.email = email.replace(email[1:4], "***", 1)
        customer.username = username.replace(username[1:4], "***", 1)
        customer_list.append(customer)
        
    dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    admin_logger.info('%s - - [%s] REQUEST[%s] %s accessed the customer database.', request.remote_addr, dt, request.method, current_user.email)

    return render_template('admin/customer_database.html', users=customer_list, title='Customer Database')


@app.route('/admin/admin_database')
@login_required
@admin_required
def admin_database():
    customers = User.query.filter_by(role='admin').all()
    customer_list = []
    for customer in customers:
        first_name = customer.first_name
        last_name = customer.last_name
        email = customer.email
        username = customer.username
        customer.first_name = first_name.replace(first_name[2:], "*", 1)
        customer.last_name = last_name.replace(last_name[2:], "*", 1)
        at = email.rfind('@')
        number = (at-1)-1 
        customer.email = email.replace(email[1:at-1],'*'*number, 1)
        customer.username = username.replace(username[2:], "*", 1)
        customer_list.append(customer)
        
    dt = datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    admin_logger.info('%s - - [%s] REQUEST[%s] %s accessed the customer database.', request.remote_addr, dt, request.method, current_user.email)

    return render_template('admin/admin_database.html', users=customer_list, title='Customer Database')


@app.route('/admin/sales')
@login_required
@admin_required
def sales():
    # line_graph = create_graph()
    current_year = datetime.utcnow().year
    current_month = datetime.utcnow().month
    current_date = date.today()
    current_day_products = Product_Bought.query.filter_by(date_bought=current_date).all()
    current_month_total = Product_Bought.query.filter(extract('year', Product_Bought.date_bought) == current_year, extract('month', Product_Bought.date_bought) == current_month).all()
    total_count = 0
    total_profit = 0
    for product in current_month_total:
        total_count += product.quantity
        total_profit += product.price
    return render_template('admin/sales.html',title='Sales Report', total_count=total_count, total_profit=total_profit, current_day_products=current_day_products)
    # return render_template('admin/sales.html',title='Sales Report' ,plot=line_graph, total_count=total_count, total_profit=total_profit, current_day_products=current_day_products)

@app.route('/admin/display_feedback')
#@login_required
#@admin_required
def feedback():
    # keysize = 2048
    private_keyfile = "a_private.pem"
    public_keyfile = "a_public.pem"
    
    # keypair = rsa.generate_keypair(keysize)
    
    # rsa.write_private_key(keypair, private_keyfile)
    # rsa.write_public_key(keypair, public_keyfile)
    
    # private_key = rsa.read_private_key(private_keyfile)
    # public_key = rsa.read_public_key(public_keyfile)

    # read keypair from files
    private_key = rsa.read_private_key(private_keyfile)
    public_key = rsa.read_public_key(public_keyfile)



    feedbacks = Feedbackform.query.all()
    feedback_list = []
    for feedback in feedbacks:
        email_data = feedback.email
        phone_data = feedback.phone_number
        message_data = feedback.message
        feedback.email = rsa.decrypt(private_key, email_data).decode("utf8")
        feedback.phone_number = rsa.decrypt(private_key, phone_data).decode("utf8")
        message = rsa.decrypt(private_key, message_data).decode("utf8")
        feedback.message = message
        feedback_list.append(feedback)
    return render_template('admin/display_feedback.html', title='Feedbacks', feedbacks=feedback_list)


@app.route('/show-monitor/admin-logs')
# @login_required
# @admin_required
def admin_logs_monitor():

    monitoring_list =[]
    with open('logs/admin.log') as f:
        lines = [line.rstrip('\n') for line in f]
        print("hi" + str(lines))
        for line in lines:
            if 'INFO' not in str(line):
                monitoring_list.append(line)
        if len(monitoring_list) < 2:
            monitoring_list.append('No Events require attention.') 
    return render_template('admin/monitoring.html', title = 'Admin Logs', monitor_list=monitoring_list)


@app.route('/show-monitor/error-logs')
# # @login_required
# # @admin_required
def error_logs_monitor():
    monitoring_list =[]
    with open('logs/error.log') as f:
        lines = [line.rstrip('\n') for line in f]
        print("hi" + str(lines))
        for line in lines:
            if 'INFO' not in str(line):
                monitoring_list.append(line)
        if len(monitoring_list) < 2:
            monitoring_list.append('No Events require attention.') 
    return render_template('admin/monitoring.html', title = 'Error Logs', monitor_list=monitoring_list)


@app.route('/show-monitor/product-logs')
# # @login_required
# # @admin_required
def product_logs_monitor():
    monitoring_list =[]
    with open('logs/error.log') as f:
        lines = [line.rstrip('\n') for line in f]
        print("hi" + str(lines))
        for line in lines:
            if 'INFO' not in str(line):
                monitoring_list.append(line)
        if len(monitoring_list) < 2:
            monitoring_list.append('No Events require attention.') 
    return render_template('admin/monitoring.html', title = 'Product Logs', monitor_list=monitoring_list)


@app.route('/show-monitor/root-logs')
# # @login_required
# # @admin_required
def root_logs_monitor():
    monitoring_list =[]
    with open('logs/root.log') as f:
        lines = [line.rstrip('\n') for line in f]
        print("hi" + str(lines))
        for line in lines:
            if 'INFO' not in str(line):
                monitoring_list.append(line)
        if len(monitoring_list) < 2:
            monitoring_list.append('No Events require attention.') 
    return render_template('admin/monitoring.html', title = 'Root Logs', monitor_list=monitoring_list)


@app.route('/show-monitor/users-logs')
# # @login_required
# # @admin_required
def users_logs_monitor():
    monitoring_list =[]
    with open('logs/users.log') as f:
        lines = [line.rstrip('\n') for line in f]
        print("hi" + str(lines))
        for line in lines:
            if 'INFO' not in str(line):
                monitoring_list.append(line)
        if len(monitoring_list) < 2:
            monitoring_list.append('No Events require attention.') 
    return render_template('admin/monitoring.html', title = 'Product Logs', monitor_list=monitoring_list)


@app.route('/admin/monitor')
# @login_required
# @admin_required
def monitor_menu():
    return render_template('admin/monitor.html', title = 'Monitoring Logs')

@app.route('/show-logs')
@login_required
#@admin_required
def show_logs():
    return render_template('admin/showlogs.html')

@app.route('/show-logs/admin-logs')
@login_required
#@admin_required
def admin_logs():
    with open('logs/admin.log') as f:
        output = f.readlines()
        return "<br><br>".join(output)

@app.route('/show-logs/error-logs')
@login_required
#@admin_required
def error_logs():
    with open('logs/error.log') as f:
        output = f.readlines()
        return "<br><br>".join(output)

@app.route('/show-logs/product-logs')
@login_required
#@admin_required
def product_logs():
    with open('logs/product.log') as f:
        output = f.readlines()
        return "<br><br>".join(output)

@app.route('/show-logs/root-logs')
@login_required
#@admin_required
def root_logs():
    with open('logs/root.log') as f:
        output = f.readlines()
        return "<br><br>".join(output)

@app.route('/show-logs/users-logs')
@login_required
#@admin_required
def users_logs():
    with open('logs/users.log') as f:
        output = f.readlines()
        return "<br><br>".join(output)

@app.route('/admin/logs')
@login_required
#@admin_required
def log_menu():
    return render_template('admin/logs.html', title = 'Logs')