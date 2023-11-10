from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from functools import wraps


app = Flask(__name__)
app.secret_key = 'your_secret_key'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'adminpassword'



def login_required(view_func):
    @wraps(view_func)
    def check_login(*args, **kwargs):
        if 'username' in session:
            return view_func(*args, **kwargs)
        else:
            flash('You need to log in to access this page.')
            return redirect(url_for('login'))
    return check_login


def admin_required(view_func):
    @wraps(view_func)
    def check_admin(*args, **kwargs):
        if 'admin' in session and session['admin'] == True:
            return view_func(*args, **kwargs)
        else:
            flash('You need to log in as an admin to access this page.')
            return redirect(url_for('admin_login'))
    return check_admin


@app.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')


@app.route('/')
def index():
    return render_template('index.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username is already taken. Please choose a different one.')
        else:
            password = request.form['password']
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!')
            return redirect(url_for('login'))
    return render_template('register.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials.')
    return render_template('login.html')




@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have successfully logged out.')
    return redirect(url_for('index'))



@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid credentials'
            return render_template('admin_login.html', error=error)

    return render_template('admin_login.html')


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Define a route to get IP information (protected with admin_required decorator)
@app.route('/ipinfo', methods=['GET'])
@admin_required
def get_ip_info():
    ip = request.args.get('ip')
    if ip:
        url = f'http://ip-api.com/json/{ip}'
        response = requests.get(url).json()
    else:
        response = None

    return render_template('admin_dashboard.html', ip_data=response)

@app.route('/phoneinfo', methods=['GET'])
@admin_required
def get_phone_info():
    phone_number = request.args.get('phone_number')
    if phone_number:
        try:
            num = phonenumbers.parse(phone_number)
            carrier_info = carrier.name_for_number(num, 'en')
            region_info = geocoder.description_for_number(num, 'en')
            is_valid = phonenumbers.is_valid_number(num)
            is_possible = phonenumbers.is_possible_number(num)
            time_zones = timezone.time_zones_for_number(num)
        except phonenumbers.phonenumberutil.NumberFormatException:
            return render_template('admin_dashboard.html', phone_error="Invalid phone number")
    else:
        carrier_info = region_info = is_valid = is_possible = time_zones = None

    return render_template('admin_dashboard.html', phone_info={
        'phone_number': phone_number,
        'is_valid': is_valid,
        'is_possible': is_possible,
        'carrier': carrier_info,
        'region': region_info,
        'time_zones': time_zones,
    })


@app.route('/ipinfo2', methods=['GET'])
@login_required
def get_ip_info2():
    ip = request.args.get('ip')
    if ip:
        url = f'http://ip-api.com/json/{ip}'
        response = requests.get(url).json()
    else:
        response = None

    return render_template('user_dashboard.html', ip_data=response)

@app.route('/phoneinfo2', methods=['GET'])
@login_required
def get_phone_info2():
    phone_number = request.args.get('phone_number')
    if phone_number:
        try:
            num = phonenumbers.parse(phone_number)
            carrier_info = carrier.name_for_number(num, 'en')
            region_info = geocoder.description_for_number(num, 'en')
            is_valid = phonenumbers.is_valid_number(num)
            is_possible = phonenumbers.is_possible_number(num)
            time_zones = timezone.time_zones_for_number(num)
        except phonenumbers.phonenumberutil.NumberFormatException:
            return render_template('user_dashboard.html', phone_error="Invalid phone number")
    else:
        carrier_info = region_info = is_valid = is_possible = time_zones = None

    return render_template('user_dashboard.html', phone_info={
        'phone_number': phone_number,
        'is_valid': is_valid,
        'is_possible': is_possible,
        'carrier': carrier_info,
        'region': region_info,
        'time_zones': time_zones,
    })



@app.route('/admin/view_users', methods=['GET', 'POST'])
@admin_required
def view_users():
    users = User.query.all()
    if request.method == 'POST':
        if 'edit_user' in request.form:
            user_id = int(request.form['edit_user'])
            return redirect(url_for('edit_user', user_id=user_id))
        elif 'delete_user' in request.form:
            user_id = int(request.form['delete_user'])
            user = User.query.get(user_id)
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully.')
            return redirect(url_for('view_users'))
    return render_template('view_users.html', users=users)


@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get(user_id)
    if request.method == 'POST':
        new_username = request.form['new_username']
        user.username = new_username
        db.session.commit()
        flash('User information updated successfully.')
        return redirect(url_for('view_users'))
    return render_template('edit_user.html', user=user)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
