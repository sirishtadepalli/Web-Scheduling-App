"""
John Leckie, SDEV 300, 3 Oct '23

Astronomy Web App

This is a Flask web application for a simple astronomy website. It includes routes to
different pages and displays the current date and time on the homepage.
For Lab 8, there are added functionalities- logging invalid login attempts, and allowing an
existing user to change their password.
"""

import hashlib  # Required for password hashing
from datetime import datetime
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = '86753093212135889'

# Configure logging to write to security_log.txt
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

# File handler for security log
security_handler = logging.FileHandler("security_log.txt")
security_handler.setLevel(logging.INFO)

# Formatter for the log messages
security_formatter = logging.Formatter('%(asctime)s - %(message)s')
security_handler.setFormatter(security_formatter)

# Add the handler to the security logger
security_logger.addHandler(security_handler)

# Store user data in a file
USER_DATA_FILE = 'user_data.txt'
SECURITY_DATA_FILE = 'security_log.txt'

# Logger for failed login attempts
failed_login_logger = logging.getLogger


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Register users and store their information in a text file after validation.

    Returns:
        rendered template for the registration page with flash messages
    """
    flash('', 'error')  # Clears existing flash messages for the session, if any
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if password and confirm_password match
        if password != confirm_password:
            flash('Password and confirm password do not match. Please try again.',
                  'error')
        else:
            # Check if the username already exists in the file (read mode)
            with open(USER_DATA_FILE, 'r', encoding='utf-8') as file:
                for line in file:
                    stored_username, _ = line.strip().split(':')
                    if username == stored_username:
                        flash('Username already exists. Choose another username or return'
                              ' to Login via below link.', 'error')
                        return render_template('register.html')

            # Validate password complexity
            if not (len(password) >= 12 and any(c.isupper() for c in password)
                    and any(c.islower() for c in password)
                    and any(c.isdigit() for c in password)
                    and any(not c.isalnum() for c in password)):
                flash('Password does not meet complexity requirements', 'error')
            # Check for spaces in username and password
            elif ' ' in username or ' ' in password:
                flash('Username and password cannot contain spaces.', 'error')
            else:
                # Hash the password before storing it (for security)
                hashed_password = hashlib.sha256(password.encode()).hexdigest()

                # Write user data to the file (append mode)
                with open(USER_DATA_FILE, 'a', encoding='utf-8') as file:
                    file.write(f'{username}:{hashed_password}\n')
                    flash('Registered! Return to Login below.', 'success')

    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    """
    Authenticate users and log them in if valid credentials are provided.

    Returns:
        rendered template for login page with flash messages
    """
    flash('', 'error')  # Clears existing flash messages for the session, if any
    reg_message = session.pop('reg_message', None)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the provided password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Ensure username and hashed password match in user_data.txt
        with open(USER_DATA_FILE, 'r', encoding='utf-8') as file:  # Opens file in read mode
            for line in file:
                stored_username, stored_hashed_password = line.strip().split(':')
                if username == stored_username and hashed_password == stored_hashed_password:
                    flash('Login successful', 'success')
                    session['username'] = username
                    print(f'User {username} logged in')  # DEBUG
                    session['logged_in'] = True  # Sets session as logged in. Important.
                    return redirect(url_for('home'))

        # Log the failed login attempt
        failed_login_message = (f'Failed login attempt for username: {username} from '
                                f'IP: {request.remote_addr}')
        security_logger.info(failed_login_message)

        flash('Invalid username or password', 'error')

    return render_template('login.html', reg_message=reg_message)


@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    """
       If the user is logged in, it verifies the current password, runs the same checks on the
       candidate new one, and updates the user's password in the file if all checks pass.

       Returns:
           Updates user_data.txt with user's new password, once candidate passwords pass checks.

       """
    # Check if the user is logged in, if not, redirect to the login page
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    flash('', 'error')  # Clears existing flash messages for the session, if any

    if request.method == 'POST':

        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        print("Debug: username =", session.get("username"))
        print("Debug: current_password =", current_password)
        print("Debug: new_password =", new_password)
        print("Debug: confirm_new_password =", confirm_new_password)

        # Ensure current password and stored password are a match
        with open(USER_DATA_FILE, "r", encoding="utf-8") as file:
            for line in file:
                stored_username, stored_hashed_password = line.strip().split(":")
                # hashed_current_password = hashlib.sha256(current_password.encode()).hexdigest()
                if session.get("username") == stored_username:
                    print("Debug: Found this user")
                    if hashlib.sha256(
                            current_password.encode()).hexdigest() != stored_hashed_password:
                        print("Debug: Issuing flash message INCORRECT PW")
                        flash("Current password is incorrect. Try again.",
                              "error")
                        return redirect(url_for("update_password"))

                    # Check for spaces in username and password
                    if " " in new_password:
                        print("Debug: Issuing flash message SPACES")
                        flash("Password cannot contain spaces.",
                              "error")
                        return redirect(url_for("update_password"))

                    # Check if the new password and confirm password match
                    if new_password != confirm_new_password:
                        print("Debug: Issuing flash message NEW/CONFIRM MISMATCH")
                        flash("New password and confirm password do not match. Try again.",
                              "error")
                        return redirect(url_for("update_password"))

                    # Password complexity validation (same as registration)
                    if not (
                            len(new_password) >= 12
                            and any(c.isupper() for c in new_password)
                            and any(c.islower() for c in new_password)
                            and any(c.isdigit() for c in new_password)
                            and any(not c.isalnum() for c in new_password)
                    ):
                        print("Debug: Issuing flash message COMPLEXITY FOR THE LOSE")
                        flash("New password does not meet complexity requirements",
                              "error")
                        return redirect(url_for("update_password"))

                    # Check if the new password is in CommonPasswords.txt
                    with open("static/CommonPasswords.txt", "r",
                              encoding="utf-8") as common_passwords_file:
                        print("Debug: Comparing COMMON PASSWORD LIST")
                        common_passwords = [line.strip() for line in common_passwords_file]

                    if new_password in common_passwords:
                        print("Debug: Issuing flash message COMMON PASSWORD FOUND")
                        flash("New password is commonly used. Choose a different password.",
                              "error")
                        return redirect(url_for("update_password"))

                    # Hash the new password before storing it (for security)
                    hashed_new_password = hashlib.sha256(new_password.encode()).hexdigest()

                    # Update the user's password in the file
                    updated_lines = []
                    with open(USER_DATA_FILE, "r", encoding="utf-8") as file_read:
                        print("Debug: Opening File to update")
                        for line_change in file_read:
                            stored_username, _ = line_change.strip().split(":")
                            if session.get("username") == stored_username:
                                print("Debug: Usernames match")
                                updated_line = f'{session.get("username")}:{hashed_new_password}\n'
                                updated_lines.append(updated_line)
                                print("Debug: Line updated")
                            else:
                                print("Debug: Username not found, nonsense appended")
                                updated_lines.append(line_change)

                    with open(USER_DATA_FILE, "w", encoding="utf-8") as file_write:
                        file_write.writelines(updated_lines)

                    print("Debug: Issuing Flash Password updated successfully")
                    flash("Password updated successfully", "success")
                    return redirect(url_for("home"))

    return render_template("update_password.html")


@app.route('/')
def home():
    """
    Render the home page of the astronomy website.
    Redirects the user to the login page if they are not logged in.

    Returns:
        rendered template with current time
    """
    # Check if the user is logged in, if not, redirect to the login page
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    current_time = datetime.now()
    return render_template('index.html', current_time=current_time)


@app.route('/telescope_time')
def telescope_time():
    """
    Render the telescope time sign-up page.

    Returns:
        rendered template for telescope time page
    """
    # Check if the user is logged in, if not, redirect to the login page
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    return render_template('telescope_time.html')


@app.route('/planetarium')
def planetarium():
    """
    Render the planetarium volunteer page.

    Returns:
        rendered template for planetarium volunteer page
    """
    # Check if the user is logged in, if not, redirect to the login page
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    return render_template('planetarium.html')


@app.route('/logout')
def logout():
    """
    Log users out by clearing their session data.

    Returns:
        Redirects to the login page with a logout flash message
    """
    # Clear the user's session data to log them out
    session.clear()
    flash('Logout Successful - See you next time!', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()
