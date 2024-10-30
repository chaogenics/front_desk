from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from pathlib import Path
import configparser
import bcrypt
#import pwinput
import sqlite3
import os

def on_closing():
	add_user.destroy()
	login.destroy()
	
#used to check for first run
first_run_flag = False

#config file name
config_file = 'config.ini'
db_name = 'front_desk.db'

#returns connection/cursor whenever sql access needed
def return_conn(db_file_path):
	conn = sqlite3.connect(db_file_path)
	cur = conn.cursor()

	return conn,cur

#open config file and assign values if exists
def open_config():
	global db_file_path
	#global first_run_flag

	config = configparser.ConfigParser()
	myfile = Path(config_file)  #Path of your .ini file
	config.read(myfile)
	file_path = config.get("Database","db_dir")
	file_name = config.get("Database","db_name")
	db_file_path = file_path.strip() + file_name.strip()
	#first_run_flag = config.get("Status","first_run_flag")

#create the config file if it doesn't exist
def create_config():
	messagebox.showwarning(title='Select Path', message='Select database path')
	path = filedialog.askdirectory()
	fh = open(config_file,'w')
	fh.write('[Database]')
	fh.write('\n[Status]')
	fh.close()

	config = configparser.ConfigParser()
	myfile = Path(config_file)  #Path of your .ini file
	config.read(myfile)
	config.set('Database', 'db_dir', path+'/')
	config.set('Database', 'db_name', db_name)
	#config.set('Status', 'first_run_flag', 'False')
	config.write(myfile.open("w"))
	open_config()

#creates database and table(s) in location specified in ini 
def create_db():
	conn,cur = return_conn(db_file_path)

	cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id VARCHAR PRIMARY KEY NOT NULL UNIQUE,
        fname TEXT,
        lname TEXT,
        passwd VARCHAR,
        admin BOOLEAN)
    ''')

	cur.execute('''
    CREATE TABLE IF NOT EXISTS laundry (
        date DATE,
        room_num VARCHAR,
        fname TEXT,
        lname TEXT,
        amount VARCHAR,
        load_num VARCHAR)
    ''')
	result = messagebox.showinfo(title="Database",message="Database and tables created")


#test for config file to open or create it
if os.path.exists(config_file):
	open_config()
else:
	create_config()

#if database is not found, look for it or create a new one
if not os.path.exists(db_file_path):
	result = messagebox.askyesno("Warning", "Database not found! Create new database?")
	if result:
		create_db()
	else:
		create_config()

def clear_user():
	global first_run_flag
	entry_username.delete(0,END)
	entry_password.delete(0,END)
	entry_first_name.delete(0,END)
	entry_last_name.delete(0,END)
	checkbox_var.set(0)

	if first_run_flag:
		first_run_flag = False
		return_to_login()
	else:
		entry_first_name.focus_set()

def create_user():
	conn,cur = return_conn(db_file_path)
	#get the user id and password from entry fields
	user_id = entry_username.get()
	unhashed = entry_password.get()
	fname = entry_first_name.get()
	lname = entry_last_name.get()
	admin = checkbox_var.get()

	if user_id == "" or unhashed == "" or fname == "" or lname == "" or admin == "":
		messagebox.showerror("Update Failed", "Please fill in all fields")
		return

	#change to bytes
	unhashed = bytes(unhashed,encoding='utf-8')

	#salt it
	passwd = bcrypt.hashpw(unhashed, bcrypt.gensalt())
	passwd = passwd.decode('utf-8') #must decode when saving to db or it will not save correctly

	cur.execute('''INSERT INTO Users
		(user_id, fname, lname, passwd, admin) VALUES ( ?, ?, ?, ?, ?)''',
		( user_id, fname, lname, passwd, admin ) )

	conn.commit()
	au_status.config(text = "User "+user_id+" has been added", anchor=W)

	clear_user()

# Function to validate the login
def validate_login():
    conn,cur = return_conn(db_file_path)
    user_id = username_entry.get()
    unhashed_temp = password_entry.get()

    if user_id == "" or unhashed_temp == "":
        messagebox.showerror("Login Failed", "Missing user name or password!")
        return

    cur.execute('SELECT passwd FROM users WHERE user_id = ? ', (user_id, ))
    hashed = bytes(cur.fetchone()[0],encoding='utf-8')

    unhashed_temp = bytes(unhashed_temp, encoding='utf-8')

    if bcrypt.checkpw(unhashed_temp, hashed):
        open_add_user()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

#first_run_check() checks to see if user data in table
#if not, forced to add a user
def first_run_check():
	global first_run_flag
	conn,cur = return_conn(db_file_path)
	data = cur.execute('SELECT * FROM users')
	if len(list(data)) > 0:
		return
	else:
		messagebox.showerror("First Run", "Please add user to continue")
		first_run_flag = True
		open_add_user()


def open_add_user():
    login.withdraw()
    add_user.deiconify()
    entry_first_name.focus_set()

def return_to_login():
    add_user.withdraw()
    login.deiconify()

################
##Login Screen##
################

login=Tk()
login.geometry("300x200")
login.title("Login Form")

# Create and place the username label and entry
username_label = Label(login, text="Userid:")
username_label.pack()

username_entry = Entry(login)
username_entry.pack()

# Create and place the password label and entry
password_label = Label(login, text="Password:")
password_label.pack()

password_entry = Entry(login, show="*")  # Show asterisks for password
password_entry.pack()

# Create and place the login button
login_button = Button(login, text="Login", command=validate_login)
login_button.pack()

# Create and place the exit button
exit_button = Button(login, text="Exit", command=on_closing)
exit_button.pack()

###################
##Add User Screen##
###################
add_user = Toplevel(login)
add_user.withdraw()
add_user.geometry("300x300")
au_main_menu = Menu(add_user)
add_user.config(menu = au_main_menu)
add_user.title("Add User")

#create a sub-menu
au_sub_menu = Menu(au_main_menu)

#add itens to menu
au_main_menu.add_cascade(label = "File",menu=au_sub_menu)

#sub menu items
au_sub_menu.add_command(label="Clear", command=clear_user)
au_sub_menu.add_command(label="Back", command=return_to_login)
au_sub_menu.add_command(label="Exit", command=on_closing)

#top frame
au_frame_top = Frame(add_user)
au_frame_top.pack(side=TOP, fill=X)

#middle frame
au_frame_middle = Frame(add_user)
au_frame_middle.pack(side=TOP, fill=X)

#second middle frame
au_frame_middle_two = Frame(add_user)
au_frame_middle_two.pack(side=TOP, fill=X)

#bottom status bar
#bottom frame for status bar
au_frame_bottom = Frame(add_user)
au_frame_bottom.pack(side=BOTTOM, fill=X)

#status bar in bottom frame
au_status = Label(au_frame_bottom, text="Current status", bd = 1, relief = SUNKEN, anchor=W)
au_status.pack(side=BOTTOM, fill=X) #fill entire row

label_create_login = Label(au_frame_top, text="Create A User: ")
label_create_login.pack()

#Labels and entry fields for user infro in middle frame
label_first_name = Label(au_frame_middle, text="User's First Name: ")
label_first_name.grid(row=0,column=0,sticky="W")

entry_first_name = Entry(au_frame_middle,width=20)
entry_first_name.grid(row=0,column=1)

label_last_name = Label(au_frame_middle,text="User's Last Name: ")
label_last_name.grid(row=1,column=0,sticky="W")

entry_last_name = Entry(au_frame_middle,width=20)
entry_last_name.grid(row=1,column=1)

label_username = Label(au_frame_middle, text="User Name: ")
label_username.grid(row=2,column=0,sticky="W")

entry_username = Entry(au_frame_middle, width=20)
entry_username.grid(row=2,column=1)

label_password = Label(au_frame_middle, text="Create Password: ")
label_password.grid(row=3,column=0,sticky="W")

entry_password = Entry(au_frame_middle, show="*", width=20)
entry_password.grid(row=3,column=1)

label_admin = Label(au_frame_middle, text="Allow Admin Access: ")
#label_admin.pack(side="left")
label_admin.grid(row=4,column=0,sticky="W")

checkbox_var = IntVar()
admin_check_button = Checkbutton(au_frame_middle, text="Allow", variable=checkbox_var)
#admin_check_button.pack(side="left")
admin_check_button.grid(row=4,column=1,sticky="W")

create_button = Button(au_frame_middle_two,text="Create User",command=create_user)
create_button.pack()

first_run_check() #check to see if users in table
login.mainloop()