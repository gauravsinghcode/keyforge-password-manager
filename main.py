from cryptography.fernet import Fernet
from email.message import EmailMessage
from decouple import config
from customtkinter import *
import sqlite3
import smtplib 
import random
import bcrypt
import shutil
import ssl
import os

class PasswordManager:

    def __init__(self):

        self.email_sender = config("EMAIL_SENDER")
        self.email_password = config("EMAIL_PASSWORD")

        self.users_db = sqlite3.connect("UsersData/users.db")
        self.keys_db = sqlite3.connect("UsersData/keys.db")

        self.main_cursor = sqlite3.Cursor(self.users_db)
        self.keys_cursor = sqlite3.Cursor(self.keys_db)

        self.user_key = None
        self.user_cursor = None
        self.user_db = None
        self.current_otp= None
        self.curr_usr_pass = None
        self.curr_username = None
        self.curr_captcha_code = None

        set_appearance_mode("Dark")
        self.window = CTk()
        self.window.title("Password Manager")
        self.window.geometry("700x500")
        self.window.resizable(False, False)
        self.login_window()
        self.create_databases()
        self.window.mainloop()


    def create_databases(self):

        self.main_cursor.execute("""CREATE TABLE IF NOT EXISTS users(
                    Username TEXT,
                    Password TEXT,
                    Email TEXT);""")
        
        self.keys_cursor.execute("""CREATE TABLE IF NOT EXISTS keys(
                    Username TEXT,
                    Key Text);""")
        
        self.users_db.commit()
        self.keys_db.commit()


    def login(self):
        login_username = login_username_entry.get()
        login_password = login_password_entry.get()

        if login_password == "" or login_username == "":
            text_label.configure(text="Username or Password is mandatory!")
        else:
            try:
                if login_username != "" and login_password != "":
                    self.main_cursor.execute("SELECT Password FROM users WHERE Username = ?;", [login_username])
                    user_pass = self.main_cursor.fetchone()

                    self.keys_cursor.execute("SELECT Key FROM keys WHERE Username = ?;", [login_username])
                    fetch_user_key = self.keys_cursor.fetchone()
                    self.user_key = fetch_user_key[0]

                    if bcrypt.checkpw(login_password.encode("utf-8"), user_pass[0]):
                            self.user_db = sqlite3.connect(f"UsersData/{login_username}.db")
                            self.user_cursor = sqlite3.Cursor(self.user_db)
                            self.curr_usr_pass = user_pass[0]
                            self.curr_username = login_username
                            login_frame.forget()
                            self.main_window()
                    else:
                        text_label.configure(text="Invlaid Username or Password!")
            except TypeError:
                text_label.configure(text="Invlaid Username or Password!")


    def signup(self):
        sign_username = sign_username_entry.get()
        sign_password = sign_password_entry.get()
        sign_email = sign_email_entry.get()
        confirm_password = sign_confirm_password_entry.get()
        crypto_key = Fernet.generate_key()

        if sign_username == "" or len(sign_username) < 5:
            msg_label.configure(text="Username should contain 5 or more characters!")
        elif sign_password == "" or len(sign_password ) < 8:
            msg_label.configure(text="Password should contain 8 or more symbols!")
        elif sign_email == "" or "@" not in sign_email:
            msg_label.configure(text="Invalid email address!")
        elif sign_password != confirm_password:
            msg_label.configure(text="Password Does not match!")
        else:
            sign_password_byte = sign_password.encode("utf-8")
            hassed_sign_password = bcrypt.hashpw(sign_password_byte, bcrypt.gensalt())
            self.main_cursor.execute("INSERT INTO users (Username, Password, Email) VALUES (?,?,?)", (sign_username, hassed_sign_password, sign_email))
            self.keys_cursor.execute("INSERT INTO keys (Username, Key) VALUES (?, ?)", (sign_username, crypto_key))
            self.user_db = sqlite3.connect(f"UsersData/{sign_username}.db")

            self.users_db.commit()
            self.keys_db.commit()
            sign_frame.forget()
            self.login_window()


    def save_user_passwords(self):
        cypher_suite = Fernet(self.user_key)
        saved_appname = app_name_entry.get()
        saved_username = pass_username_entry.get()
        saved_password = pass_password_entry.get()
        saved_password_encrpyt = cypher_suite.encrypt(saved_password.encode())
        
        self.user_cursor.execute("""CREATE TABLE IF NOT EXISTS passwords(
                            AppName TEXT,
                            Username TEXT,
                            Password Text);""")
        
        self.user_cursor.execute("INSERT INTO passwords (AppName, Username, Password) VALUES (?,?,?)", (saved_appname, saved_username, saved_password_encrpyt))

        self.user_cursor.execute("SELECT * FROM passwords")

        self.user_db.commit()

        saved_appname = app_name_entry.delete(0, "end")
        saved_username = pass_username_entry.delete(0, "end")
        saved_password = pass_password_entry.delete(0, "end")


    def update_slider_label(self, value):
        Capital_letters_number_label.configure(text=f"{int(Capital_letters_slider.get())}")
        small_letters_number_label.configure(text=f"{int(small_letters_slider.get())}")
        numbers_update_label.configure(text=f"{int(numbers_slider.get())}")
        symbols_update_label.configure(text=f"{int(symbols_slider.get())}")


    def fill_password(self):
        password = show_password_label.cget("text")
        pass_password_entry.insert(1, password)
        toplvl_pass_window.destroy()


    def generate_random_password(self, captcha=False):
        UPPERCASE = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q," "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
        LOWERCASE = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
        NUMBERS = ["1","2","3","4","5","6","7","8","9","0"]
        SYMBOLS = ["!", "`", "~", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "-", "+", "=", "[", "]", "{", "}", "\\", "|", ";", ":", "\"", "'", ",", "<", ".", ">", "/", "?"]

        PASSWORD = []

        if captcha:
            upperAlpha = 3
            lowerAplha = 3
            numbers = 0
            symbols = 0
        else:
            upperAlpha = int(Capital_letters_slider.get())
            lowerAplha = int(small_letters_slider.get())
            numbers = int(numbers_slider.get())
            symbols = int(symbols_slider.get())

        for i in range(0,upperAlpha):
            rndm = random.choice(UPPERCASE)
            PASSWORD.append(rndm)
        
        for j in range(0,numbers):
            rndm = random.choice(NUMBERS)
            PASSWORD.append(rndm)
        
        for k in range(0,symbols):
            rndm = random.choice(SYMBOLS)
            PASSWORD.append(rndm)

        for l in range(0,lowerAplha):
            rndm = random.choice(LOWERCASE)
            PASSWORD.append(rndm)

        random.shuffle(PASSWORD)
        PASSWORD = "".join(PASSWORD)
        self.curr_captcha_code = PASSWORD

        if not captcha:
            fill_btn.place(x=550, y=360)
            show_password_label.configure(text=f"{PASSWORD}")

    
    def search_passwords(self, search_term=""):
        cypher_suite = Fernet(self.user_key)
        
        if search_term == "":
            self.user_cursor.execute("SELECT * FROM passwords")
        else:
            self.user_cursor.execute(" SELECT * FROM passwords WHERE LOWER(AppName) LIKE LOWER(?) OR LOWER(Username) LIKE LOWER(?)", (search_term, search_term))
        
        results = self.user_cursor.fetchall()
        
        decrypted_results = []
        for row in results:
            app_name, username, encrypted_password = row
            decrypted_password = cypher_suite.decrypt(encrypted_password).decode()
            decrypted_results.append((app_name, username, decrypted_password))
        
        return decrypted_results


    def show_passwords(self):
        
        pass_win = CTk()
        pass_win.title("Saved Passwords")
        pass_win.geometry("800x600")
        pass_win.resizable(False, False)

        search_frame = CTkFrame(pass_win, width=760, height=80)
        search_frame.place(x=20, y=10)

        search_label = CTkLabel(search_frame, text="Search:", font=("Raleway", 16))
        search_label.place(x=20, y=25)

        search_entry = CTkEntry(search_frame, font=("Raleway", 16), width=400, placeholder_text="Search by app name or username...")
        search_entry.place(x=100, y=25)

        search_btn = CTkButton(search_frame, text="Search", font=("Raleway", 16), width=100)
        search_btn.place(x=520, y=25)

        clear_btn = CTkButton(search_frame, text="Clear", font=("Raleway", 16), width=100)
        clear_btn.place(x=640, y=25)

        results_label = CTkLabel(pass_win, text="Results: 0", font=("Raleway", 12))
        results_label.place(x=20, y=100)

        header_frame = CTkFrame(pass_win, width=760, height=40, fg_color="#1f538d")
        header_frame.place(x=20, y=130)

        CTkLabel(header_frame, text="App Name", font=("Raleway", 14, "bold"), text_color="white").place(x=50, y=8)
        CTkLabel(header_frame, text="Username", font=("Raleway", 14, "bold"), text_color="white").place(x=280, y=8)
        CTkLabel(header_frame, text="Password", font=("Raleway", 14, "bold"), text_color="white").place(x=510, y=8)
        CTkLabel(header_frame, text="Actions", font=("Raleway", 14, "bold"), text_color="white").place(x=680, y=8)

        scrollable_frame = CTkScrollableFrame(pass_win, width=740, height=400)
        scrollable_frame.place(x=20, y=180)

        def create_password_row(app_name, username, password, row_index):

            row_color = "#343638" if row_index % 2 == 0 else "#404040"
            
            row_frame = CTkFrame(scrollable_frame, width=720, height=50, fg_color=row_color)
            row_frame.pack(fill="x", pady=2, padx=5)
            
            app_label = CTkLabel(row_frame, text=app_name[:20] + "..." if len(app_name) > 20 else app_name, font=("Raleway", 12), width=180, anchor="w")
            app_label.place(x=20, y=15)

            user_label = CTkLabel(row_frame, text=username[:20] + "..." if len(username) > 20 else username, font=("Raleway", 12), width=180, anchor="w")
            user_label.place(x=220, y=15)
            
            password_label = CTkLabel(row_frame, text="*" * min(len(password), 12), font=("Raleway", 12), width=120, anchor="w")
            password_label.place(x=420, y=15)

            def toggle_password():
                current = password_label.cget("text")
                if "*" in current:
                    password_label.configure(text=password)
                    show_btn.configure(text="Hide")
                else:
                    password_label.configure(text="*" * min(len(password), 12))
                    show_btn.configure(text="Show")
            
            show_btn = CTkButton(row_frame, text="Show", width=50, height=25, font=("Raleway", 10), command=toggle_password)
            show_btn.place(x=560, y=12)
            
            def copy_password():
                pass_win.clipboard_clear()
                pass_win.clipboard_append(password)
                copy_btn.configure(text="Copied!")
                pass_win.after(1000, lambda: copy_btn.configure(text="Copy"))
            
            copy_btn = CTkButton(row_frame, text="Copy", width=50, height=25, font=("Raleway", 10), command=copy_password)
            copy_btn.place(x=620, y=12)

        def update_password_list(search_term=""):

            for widget in scrollable_frame.winfo_children():
                widget.destroy()
            
            results = self.search_passwords(search_term)
            results_label.configure(text=f"Results: {len(results)}")
            
            for i, (app_name, username, password) in enumerate(results):
                create_password_row(app_name, username, password, i)

        search_btn.configure(command=lambda: update_password_list(search_entry.get()))
        clear_btn.configure(command=lambda: [search_entry.delete(0, 'end'), update_password_list()])
        search_entry.bind('<KeyRelease>', lambda e: update_password_list(search_entry.get()))

        update_password_list()

        pass_win.mainloop()


    def send_email(self):

        username = otp_username_entry.get()

        self.main_cursor.execute("SELECT Email FROM users where username = (?)", [username])
        email = self.main_cursor.fetchone()[0]

        self.current_otp = random.randint(100000, 999999)
        email_receiver = email
        email_subject = "OTP Verification (Password Recovery)"
        email_body = f"""Your One-Time-Password for password recovery is {self.current_otp}.\nThis code is valid only for 15 minutes."""

        if "@" in email_receiver and email_subject != "":
            em = EmailMessage()
            em["From"] = self.email_sender
            em["To"] = email_receiver
            em["subject"] = email_subject
            em.set_content(email_body)

            context = ssl.create_default_context()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
                smtp.login(self.email_sender, self.email_password)
                smtp.sendmail(self.email_sender, email_receiver, em.as_string())
                msg_label.configure(text="OTP send successfully.")

                otp_label = CTkLabel(email_frame, text="Enter OTP", font=("Raleway", 20))
                otp_label.place(x=130, y=240)
                
                otp_entry = CTkEntry(email_frame, font=("Raleway", 20), width=350)
                otp_entry.place(x=270, y=240)

                otp_btn = CTkButton(email_frame, font=("Raleway", 20), text="Verify OTP", command=lambda: self.verify_otp())
                otp_btn.place(x=480, y=320)
        else:
            msg_label.configure(text="Some error occured please ensure that you fill all details correctly.")


    def verify_otp(self):

        entered_otp = int(otp_entry.get())

        if entered_otp == self.current_otp:
            msg_label.configure(text="OTP Verified!")
            self.password_recovery_window()
        else:
            msg_label.configure(text="Invalid OTP")

    
    def check_password_strength(self, password):
        score = 0
        if len(password) >= 8: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*" for c in password): score += 1
        return score


    def update_password(self):

        new_password = new_pass_entry.get()
        username = recovery_username_entry.get()
        confirm_password = confirm_pass_entry.get()

        if new_password != confirm_password:
            recovery_msg_label.configure(text="Password Doesn't Match!")
        elif username == "" or new_password == "":
            recovery_msg_label.configure(text="Fill all required fields!")
        elif 0 < len(new_password) < 8:
            recovery_msg_label.configure(text="Password must contain 8 or more characters!")
        else:
            new_password_byte = new_password.encode("utf-8")
            hassed_new_password = bcrypt.hashpw(new_password_byte, bcrypt.gensalt())
            self.main_cursor.execute("UPDATE users SET password = ? WHERE USERNAME = ?", (hassed_new_password, username))
            self.users_db.commit()
            recovery_msg_label.configure(text_color="#6aab73")
            recovery_msg_label.configure(text="Password Reset Successfully. Please Login Again!")


    def export_passwords(self):
        # Not Implemented Yet!
        pass

    def import_passwords():
        # Not Implemented Yet!
        pass

    def delete_account(self):

        delete_pass_read = delete_password_entry.get()
        captcha_read = captcha_entry.get()
        isBackup = toggle_backup.get()
        confirm_deletion = confirm_checkbox.get()

        if bcrypt.checkpw(delete_pass_read.encode("utf-8"), self.curr_usr_pass):
            if captcha_read == self.curr_captcha_code:
                if isBackup:
                    print("Preparing Password Backup")
                if confirm_deletion:
                    self.main_cursor.execute("DELETE FROM users WHERE username = ?", [self.curr_username])
                    self.keys_cursor.execute("DELETE FROM keys WHERE username = ?", [self.curr_username])
                    os.remove(f"UsersData/{self.curr_username}.db")
                    setting_toplvl_window.destroy()
                    self.login_window()
                else:
                    print("Confirm Deletion First!")
            else:
                print("Invalid captcha Code!")
        else:
            print("Invalid Password!")
            

    def quit_application(self, quit):
        if quit == 1:
            self.window.destroy()
        else:
            confirm_window.destroy()


    def signup_window(self):
        global sign_frame, sign_password_entry, sign_confirm_password_entry, sign_username_entry, sign_email_entry, msg_label

        sign_frame = CTkFrame(self.window, width=660, height=460)
        sign_frame.place(x=20, y=10)

        head_label = CTkLabel(sign_frame, text="Sign Up", font=("Raleway", 30))
        head_label.place(x=265, y=10)

        username_label = CTkLabel(sign_frame, text="Username", font=("Raleway", 20))
        username_label.place(x=140, y=85)

        sign_username_entry = CTkEntry(sign_frame, font=("Raleway", 20), width=250)
        sign_username_entry.place(x=350, y=85)

        email_label = CTkLabel(sign_frame, text="Email Address", font=("Raleway", 20))
        email_label.place(x=140, y=145)

        sign_email_entry = CTkEntry(sign_frame, font=("Raleway", 20), width=250)
        sign_email_entry.place(x=350, y=145)

        password_label = CTkLabel(sign_frame, text="Password", font=("Raleway", 20))
        password_label.place(x=140, y=205)

        sign_password_entry = CTkEntry(sign_frame, font=("Raleway", 20), width=250, show="*")
        sign_password_entry.place(x=350, y=205)

        confirm_password_label = CTkLabel(sign_frame, text="Confirm Password", font=("Raleway", 20))
        confirm_password_label.place(x=140, y=265)

        sign_confirm_password_entry = CTkEntry(sign_frame, font=("Raleway", 20), width=250, show="*")
        sign_confirm_password_entry.place(x=350, y=265)

        signup_btn = CTkButton(sign_frame, font=("Raleway", 20), width=250, text="Sign Up", command=lambda: self.signup())
        signup_btn.place(x=220, y=325)

        login_label = CTkLabel(sign_frame, text="Already have an account ?", font=("Raleway", 20))
        login_label.place(x=135, y=385)

        login_btn = CTkButton(sign_frame, text="Login Here", font=("Raleway", 20), fg_color="#2a2a2b", text_color="#1f6aa5", hover_color="#2a2a2b", width=100, command=lambda: self.login_window())
        login_btn.place(x=385, y=385)

        msg_label = CTkLabel(sign_frame, text="", font=("Raleway", 20), text_color="#e82e34")
        msg_label.place(x=135, y=430)


    def login_window(self):
        global login_frame, login_password_entry, login_username_entry, text_label

        login_frame = CTkFrame(self.window, width=660, height=460)
        login_frame.place(x=20, y=20)

        head_label = CTkLabel(login_frame, text="Login", font=("Raleway", 30))
        head_label.place(x=290, y=20)

        username_label = CTkLabel(login_frame, text="Username", font=("Raleway", 20))
        username_label.place(x=170, y=120)

        login_username_entry = CTkEntry(login_frame, font=("Raleway", 20), width=250)
        login_username_entry.place(x=300, y=120)

        password_label = CTkLabel(login_frame, text="Password", font=("Raleway", 20))
        password_label.place(x=170, y=180)

        login_password_entry = CTkEntry(login_frame, font=("Raleway", 20), width=250, show="*")
        login_password_entry.place(x=300, y=180)

        login_btn = CTkButton(login_frame, font=("Raleway", 20), width=250, text="Login", command= self.login)
        login_btn.place(x=220, y=260)

        text_label = CTkLabel(login_frame, text="", font=("Raleway", 20), text_color="#e82e34")
        text_label.place(x=200, y=315)

        forget_password_btn = CTkButton(login_frame, text="Forget Password ?", font=("Raleway", 20), fg_color="#2a2a2b", text_color="#1f6aa5", hover_color="#2a2a2b", command=lambda: self.email_window())
        forget_password_btn.place(x=250, y=360)

        sign_label = CTkLabel(login_frame, text="Don't have an account ?", font=("Raleway", 20))
        sign_label.place(x=165, y=400)

        sign_btn = CTkButton(login_frame, text="Create One", font=("Raleway", 20), fg_color="#2a2a2b", text_color="#1f6aa5", hover_color="#2a2a2b", width=100, command=lambda: self.signup_window())
        sign_btn.place(x=390, y=400)


    def main_window(self):
        global main_frame, pass_username_entry, pass_password_entry, app_name_entry, search_entry

        main_frame = CTkFrame(self.window, width=660, height=460)
        main_frame.place(x=20, y=20)

        head_label = CTkLabel(main_frame, text="Password Manager", font=("Raleway", 30))
        head_label.place(x=210, y=20)

        app_name_label = CTkLabel(main_frame, text="App Name", font=("Raleway", 20))
        app_name_label.place(x=170, y=100)

        app_name_entry = CTkEntry(main_frame, font=("Raleway", 20), width=250)
        app_name_entry.place(x=300, y=100)

        username_label = CTkLabel(main_frame, text="Username", font=("Raleway", 20))
        username_label.place(x=170, y=160)

        pass_username_entry = CTkEntry(main_frame, font=("Raleway", 20), width=250)
        pass_username_entry.place(x=300, y=160)
 
        password_label = CTkLabel(main_frame, text="Password", font=("Raleway", 20))
        password_label.place(x=170, y=220)

        pass_password_entry = CTkEntry(main_frame, font=("Raleway", 20), width=250)
        pass_password_entry.place(x=300, y=220)

        create_rndm_pass_btn = CTkButton(main_frame, font=("Raleway", 20), width=250, text="Create Random Password", fg_color="#2a2a2b", text_color="#1f6aa5", hover_color="#2a2a2b", command = lambda: self.random_pass_window())
        create_rndm_pass_btn.place(x=190, y=300) 

        create_btn = CTkButton(main_frame, font=("Raleway", 20), width=250, text="Save Password", command=lambda: self.save_user_passwords())
        create_btn.place(x=190, y=360)

        show_btn = CTkButton(main_frame, font=("Raleway", 20), width=250, text="Show Passwords", command=lambda: self.show_passwords())
        show_btn.place(x=190, y=410)

        settings_btn = CTkButton(main_frame, font=("Raleway", 20), width=100, text="Settings", command=lambda: self.settings_window())
        settings_btn.place(x=550, y=20)


    def random_pass_window(self):
        global random_pass_frame, Capital_letters_number_label, small_letters_number_label, numbers_update_label, symbols_update_label, Capital_letters_slider, small_letters_slider, symbols_slider, numbers_slider, toplvl_frame, toplvl_pass_window, fill_btn, show_password_label

        toplvl_pass_window = CTkToplevel(self.window)
        toplvl_pass_window.title("Generate Random Password")
        toplvl_pass_window.geometry("700x500")
        toplvl_pass_window.resizable(False, False)

        toplvl_frame = CTkFrame(toplvl_pass_window, width=660, height=460)
        toplvl_frame.place(x=20, y=20)

        head_label = CTkLabel(toplvl_frame, text="Generate Random Password", font=("Raleway", 30))
        head_label.place(x=125, y=20)

        Capital_letters_label = CTkLabel(toplvl_frame, text="Capital Letters", font=("Raleway", 20))
        Capital_letters_label.place(x=110, y=100)

        Capital_letters_slider = CTkSlider(toplvl_frame, width=250, from_=0, to=20, number_of_steps=20, command=self.update_slider_label)
        Capital_letters_slider.set(0)
        Capital_letters_slider.place(x=260, y=105)

        Capital_letters_number_label = CTkLabel(toplvl_frame, text=0, font=("Raleway", 20))
        Capital_letters_number_label.place(x=530, y=100)

        small_letters_label = CTkLabel(toplvl_frame, text="Small Letters", font=("Raleway", 20))
        small_letters_label.place(x=110, y=160)

        small_letters_slider = CTkSlider(toplvl_frame, width=250, from_=0, to=20, number_of_steps=20, command=self.update_slider_label)
        small_letters_slider.set(0)
        small_letters_slider.place(x=260, y=165)

        small_letters_number_label = CTkLabel(toplvl_frame, text=0, font=("Raleway", 20))
        small_letters_number_label.place(x=530, y=160)

        numbers_label = CTkLabel(toplvl_frame, text="Numbers", font=("Raleway", 20))
        numbers_label.place(x=110, y=220)

        numbers_slider = CTkSlider(toplvl_frame, width=250, from_=0, to=20, number_of_steps=20, command=self.update_slider_label)
        numbers_slider.set(0)
        numbers_slider.place(x=260, y=225)

        numbers_update_label = CTkLabel(toplvl_frame, text=0, font=("Raleway", 20))
        numbers_update_label.place(x=530, y=220)

        symbols_label = CTkLabel(toplvl_frame, text="Symbols", font=("Raleway", 20))
        symbols_label.place(x=110, y=280)

        symbols_slider = CTkSlider(toplvl_frame, width=250, from_=0, to=20, number_of_steps=20, command=self.update_slider_label)
        symbols_slider.set(0)
        symbols_slider.place(x=260, y=285)

        symbols_update_label = CTkLabel(toplvl_frame, text=0, font=("Raleway", 20))
        symbols_update_label.place(x=530, y=280)
        
        create_btn = CTkButton(toplvl_frame, font=("Raleway", 20), width=250, text="Generate Password", command=self.generate_random_password)
        create_btn.place(x=190, y=360)

        fill_btn = CTkButton(toplvl_frame, font=("Raleway", 20), width=100, text="Fill", command=self.fill_password) 

        show_password_label = CTkLabel(toplvl_frame, text="", font=("Raleway", 20))
        show_password_label.place(x=50, y=420)

        toplvl_pass_window.mainloop()


    def email_window(self):
        global otp_username_entry, msg_label, otp_entry, otp_disabled, toplvl_email_window, email_frame

        toplvl_email_window = CTkToplevel(self.window)
        toplvl_email_window.title("Email Verfication")
        toplvl_email_window.geometry("700x500")
        toplvl_email_window.resizable(False, False)

        email_frame = CTkFrame(toplvl_email_window, width=660, height=460)
        email_frame.place(x=20, y=20)

        head_label = CTkLabel(email_frame, text="Verify It's You", font=("Raleway", 20))
        head_label.place(x=270, y=20)

        otp_username_label = CTkLabel(email_frame, text="Enter Username", font=("Raleway", 20))
        otp_username_label.place(x=100, y=80)

        otp_username_entry = CTkEntry(email_frame, font=("Raleway", 20), width=350)
        otp_username_entry.place(x=270, y=80)

        email_btn = CTkButton(email_frame, font=("Raleway", 20), text="Send OTP", command=lambda: self.send_email())
        email_btn.place(x=480, y=160)

        msg_label = CTkLabel(email_frame, text="", font=("Raleway", 20))
        msg_label.place(x=235, y=420)

        toplvl_email_window.mainloop()


    def password_recovery_window(self):
        global confirm_pass_entry, recovery_username_entry, recovery_msg_label, new_pass_entry

        pass_recovery_frame = CTkFrame(toplvl_email_window, width=660, height=460)
        pass_recovery_frame.place(x=20, y=20)

        head_label = CTkLabel(pass_recovery_frame, text="Reset Password", font=("Raleway", 20))
        head_label.place(x=270, y=20)

        recovery_username_label = CTkLabel(pass_recovery_frame, text="Username", font=("Raleway", 20))
        recovery_username_label.place(x=80, y=80)

        recovery_username_entry = CTkEntry(pass_recovery_frame, font=("Raleway", 20), width=350)
        recovery_username_entry.place(x=270, y=80)

        new_pass_label = CTkLabel(pass_recovery_frame, text="New Password", font=("Raleway", 20))
        new_pass_label.place(x=80, y=160)

        new_pass_entry = CTkEntry(pass_recovery_frame, font=("Raleway", 20), width=350)
        new_pass_entry.place(x=270, y=160)

        confirm_pass_label = CTkLabel(pass_recovery_frame, text="Confirm Password", font=("Raleway", 20))
        confirm_pass_label.place(x=80, y=240)

        confirm_pass_entry = CTkEntry(pass_recovery_frame, font=("Raleway", 20), width=350)
        confirm_pass_entry.place(x=270, y=240)

        reset_btn = CTkButton(pass_recovery_frame, font=("Raleway", 20), text="Reset Password", command=lambda: self.update_password())
        reset_btn.place(x=260, y=320)

        recovery_msg_label = CTkLabel(pass_recovery_frame, text="", font=("Raleway", 20), text_color="#e82e34")
        recovery_msg_label.place(x=80, y=400)

        toplvl_email_window.mainloop()


    def delete_account_window(self):
        global delete_password_entry, captcha_entry, confirm_checkbox, toggle_backup

        self.generate_random_password(captcha=True)
        
        settings_frame.forget()

        deletion_frame = CTkFrame(setting_toplvl_window, width=660, height=460)
        deletion_frame.place(x=20, y=20)

        head_label = CTkLabel(deletion_frame, text="Delete Account", font=("Raleway", 25))
        head_label.place(x=250, y=10)

        delete_password_label = CTkLabel(deletion_frame, text="Password", font=("Raleway", 20))
        delete_password_label.place(x=120, y=80)

        delete_password_entry = CTkEntry(deletion_frame, show="*", font=("Raleway", 20), width=300)
        delete_password_entry.place(x=250, y=80)

        captcha_label = CTkLabel(deletion_frame, text="Captcha", font=("Raleway", 20))
        captcha_label.place(x=120, y=140)

        captcha_entry = CTkEntry(deletion_frame, font=("Raleway", 20), width=300)
        captcha_entry.place(x=250, y=140)

        captcha_frame = CTkFrame(deletion_frame, width=430, height=100)
        captcha_frame.place(x=120, y=200)

        captcha_text_label = CTkLabel(captcha_frame, text=self.curr_captcha_code, font=("Raleway", 25))
        captcha_text_label.place(x=155, y=30)

        confirm_checkbox = CTkCheckBox(deletion_frame, text="I Hereby confirm that I want to delete my account and all related data.")
        confirm_checkbox.place(x=120, y=330)

        toggle_backup = CTkSwitch(deletion_frame, text="Backup Passwords")
        toggle_backup.place(x=120, y=375)

        confirm_delete_btn = CTkButton(deletion_frame, font=("Raleway", 20), text="Delete Account", command=lambda: self.delete_account(), fg_color="#e82e34", hover_color="#651118")
        confirm_delete_btn.place(x=250, y=415)


    def settings_window(self):
        global setting_toplvl_window, settings_frame

        setting_toplvl_window = CTkToplevel(self.window)
        setting_toplvl_window.title("Settings")
        setting_toplvl_window.geometry("700x500")
        setting_toplvl_window.resizable(False, False)
        
        settings_frame = CTkFrame(setting_toplvl_window, width=660, height=460)
        settings_frame.place(x=20, y=20)

        settings_label = CTkLabel(settings_frame, text="Settings", font=("Raleway", 25))
        settings_label.place(x=280, y=10)

        export_btn = CTkButton(settings_frame, font=("Raleway", 20), text="Export Password", command=lambda: self.update_password())
        export_btn.place(x=40, y=70)

        import_btn = CTkButton(settings_frame, font=("Raleway", 20), text="Import Password", command=lambda: self.update_password())
        import_btn.place(x=255, y=70)

        delete_acc_btn = CTkButton(settings_frame, font=("Raleway", 20), text="Delete Account", command=lambda: self.delete_account_window(), fg_color="#e82e34", hover_color="#651118")
        delete_acc_btn.place(x=470, y=70)


    def confirmation_dialog(self, title, msg):
        global confirm_window

        confirm_window = CTkToplevel(self.window)
        confirm_window.title(title)
        confirm_window.geometry("500x200")
        confirm_window.resizable(False, False)
        
        label = CTkLabel(confirm_window, text=msg, font=("Raleway", 20))
        label.place(x=120, y=50)

        ok_btn = CTkButton(confirm_window, text="OK", fg_color="#23aa4f", hover_color="#60a973", command=lambda: self.quit_application(1))
        ok_btn.place(x=300, y=120)

        cancel_btn = CTkButton(confirm_window, text="Cancel", fg_color="#e82e34", hover_color="#651118", command=lambda: self.quit_application(0))
        cancel_btn.place(x=100, y=120)

        confirm_window.mainloop()

passwordmanager = PasswordManager()