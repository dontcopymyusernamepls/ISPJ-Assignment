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
from spectrum.forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm, UpdateUserAccountForm, AddproductForm, UpdateProductForm, AdminRegisterForm, AddToCartForm, AddReviewForm, CheckOutForm
from spectrum.database import Staff, Users, User, Addproducts, Category, Items_In_Cart, Review, Customer_Payments, Product_Bought
import spectrum.MyCaesarcipher as cipher
from io import BytesIO
import onetimepass
import pyqrcode


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
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

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

        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
                flash(f'Oops! Login unsuccessful. Please check your details.', 'danger')
                return redirect(url_for('login'))
          
        # log user in
        login_user(user)
        flash('You are now logged in!')
        next = request.args.get('next')
        return redirect(next) if next else redirect(url_for('home'))
    return render_template('login.html', title='Login',form=form)

@app.route('/logout')
def logout():
    logout_user()
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
        hash_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        user.password = hash_pw
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
    flash('Your account has been deleted.', 'success')
    return redirect(url_for('home'))


#-------------------------- user page -----------------------#

@app.route('/')
@app.route('/home')
def home():

    return render_template('home.html', title='Home')
    
@app.route('/about')
def about():
    
    return render_template('about.html', title='About Us')

@app.route('/product')
def product():
    products = Addproducts.query.all()

    return render_template('product.html', title='Products', products=products)

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

@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    cart_items = Items_In_Cart.query.filter_by(user_id=current_user.id).all()
    items = 0
    for item in cart_items:
        items += 1
    return render_template('cart.html', title='Shopping Cart', current_user=current_user, cart_items=cart_items, items=items)

# Checkout  
@app.route('/checkout', methods=['POST', 'GET'])
@login_required
def checkout_details():
    form = CheckOutForm()
    cart_items = Items_In_Cart.query.filter_by(user_id=current_user.id).all()
    subtotal = 0
    total = 0
    for item in cart_items:
        product = Addproducts.query.filter_by(id=item.product_id).first()
        if product.stock < item.quantity:
            flash('{{product.name}} only has {{product.stock}} left in stock', 'danger')
            return redirect(url_for('cart'))
        else:
            subtotal += item.price
    
    total = subtotal + 10
    if form.validate_on_submit():
        full_name = form.full_name.data
        en_address = cipher.encrypt(3,form.address.data)
        postal_code = form.postal_code.data
        en_card_number = cipher.encrypt(3,form.card_number.data)
        en_cvv = cipher.encrypt(3,form.cvv.data)
        checkout_details = Customer_Payments(full_name=full_name, address=en_address, postal_code=postal_code, card_number=en_card_number, cvv=en_cvv)
        db.session.add(checkout_details)
        
        for cart_item in cart_items:
            product = Addproducts.query.filter_by(id=cart_item.product_id).first()
            product.stock = product.stock - cart_item.quantity
            product_bought = Product_Bought(quantity=cart_item.quantity, product_id=cart_item.product_id, user_id=cart_item.user_id, product_name=cart_item.name, image=cart_item.image_1, price=cart_item.price)
            db.session.add(product_bought)
            db.session.delete(cart_item)
            db.session.commit()
        flash(f'Your order has been submitted!','success')
        return redirect(url_for('thanks'))
    return render_template('checkout.html', title='Checkout',form=form, cart_items=cart_items, subtotal=subtotal, total=total)

@app.route('/thanks')
def thanks():
    return render_template('thanks.html', title='Order Confirmed')

@app.route('/verify_checkout_page')
def verify():
    return render_template('verify_checkout_page.html',title = 'Verify')

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
        flash('Your review has been added!', 'success')
        return redirect(url_for('shop'))
    return render_template('product_details.html', title="Product Details", products=products, product_reviews=product_reviews ,form=form, product_bought=product_bought)



#---------------------ADMIN-PAGE------------------------#

@app.route('/admin/register', methods=['GET', 'POST'])
#@login_required
#@admin_required
def admin_register():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('home'))
    form = AdminRegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('admin_register'))
        # add new user to the database
        user = Staff(first_name=form.first_name.data, last_name=form.last_name.data, username=form.username.data, email=form.email.data, password=form.password.data, role='admin')
        db.session.add(user)
        db.session.commit()

        # redirect to the two-factor auth page, passing username in session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('admin/register.html', form=form)

@app.route('/admin/dashboard')
@login_required
@admin_required
def dashboard():
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
        flash(f'The product {name} has been added to database!','success')
        return redirect(url_for('add_product'))
    return render_template('admin/add_product.html', form=form, title='Add a Product', categories=categories)


@app.route('/admin/display_product')
@login_required
@admin_required
def display_product():
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
        db.session.delete(product)
        db.session.commit()
        flash(f'The product {product.name} has been deleted from the product list.','success')
        return redirect(url_for('display_product'))
    flash(f'Cannot delete the product.','success')
    return redirect(url_for('display_product'))

@app.route('/admin/sales')
# @login_required
# @admin_required
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

