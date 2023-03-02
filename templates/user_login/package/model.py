import sqlite3
import json

with open('config.json') as data_file:
    config = json.load(data_file)

conn=sqlite3.connect(config['database'], check_same_thread=False)
conn.execute('PRAGMA foreign_keys=0')



def dict_factory(cursor, row):
    """This is a function used to format the json when retrieved from the  sqlite database"""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


conn.row_factory = dict_factory

conn.execute('''CREATE TABLE if not exists land
(land_id INTEGER PRIMARY KEY AUTOINCREMENT,
landowner_first_name TEXT NOT NULL,
landowner_last_name TEXT NOT NULL,
landowner_insurance_no TEXT NOT NULL,
landowner_ph_no TEXT NOT NULL,
landowneracq_date DATE DEFAULT (datetime('now','localtime')),
landowner_address TEXT NOT NULL);''')

conn.execute('''CREATE TABLE if not exists seller
(seller_id INTEGER PRIMARY KEY AUTOINCREMENT,
seller_first_name TEXT NOT NULL,
seller_last_name TEXT NOT NULL,
seller_ph_no TEXT NOT NULL,
seller_date DATE DEFAULT (datetime('now','localtime')),
seller_address TEXT NOT NULL);''')

conn.execute('''CREATE TABLE if not exists buyer
(buyer_id INTEGER PRIMARY KEY AUTOINCREMENT,
buyer_first_name TEXT NOT NULL,
buyer_last_name TEXT NOT NULL,
buyer_ph_no TEXT NOT NULL,
buy_date DATE DEFAULT (datetime('now','localtime')),
buyer_address TEXT NOT NULL);''')


conn.execute('''CREATE TABLE if not exists appointment
(app_id INTEGER PRIMARY KEY AUTOINCREMENT,
land_id INTEGER NOT NULL,
seller_id INTEGER NOT NULL,
appointment_date DATE NOT NULL,
FOREIGN KEY(land_id) REFERENCES land(land_id),
FOREIGN KEY(seller_id) REFERENCES seller(seller_id));''')

conn.execute('''CREATE TABLE if not exists caveat
(code INTEGER PRIMARY KEY,
name TEXT NOT NULL,
brand TEXT NOT NULL,
description TEXT);''')

conn.execute('''CREATE TABLE if not exists landtitle
(land_title_no INTEGER PRIMARY KEY,
name TEXT NOT NULL,
available TEXT NOT NULL,
description TEXT);''')

conn.execute('''CREATE TABLE if not exists location
(plot_id INTEGER PRIMARY KEY,
name TEXT NOT NULL,
lc_id INTEGER NOT NULL,
size INTEGER NOT NULL);''')

conn.execute('''CREATE TABLE if not exists procedure
(buy_code INTEGER PRIMARY KEY,
name TEXT NOT NULL,
cost INTEGER NOT NULL,
description TEXT);''')

conn.execute('''CREATE TABLE if not exists buy_sell_transaction
(land_id INTEGER PRIMARY KEY,
buy_code INTEGER NOT NULL,
buy_date DATE NOT NULL,
seller_id INTEGER,
buyer_id INTEGER,
land_title_no INTEGER,
FOREIGN KEY(land_id) REFERENCES land(land_id),
FOREIGN KEY(seller_id) REFERENCES seller(seller_id),
FOREIGN KEY(buy_code) REFERENCES buy_procedure(buy_code),
FOREIGN KEY(buyer_id) REFERENCES buyer(buyer_id),
FOREIGN KEY(land_title_no) REFERENCES landtitle(land_title_no));''')


#conn.execute('''CREATE TABLE if not exists projects
#(project_id INTEGER NOT NULL,
#project_name TEXT NOT NULL,
#acquired_date DATE NOT NULL,
#project_owner TEXT,
#project_location TEXT,
#cost INTEGER,
#PRIMARY KEY(project_id, project_name, acquired_date),
#FOREIGN KEY(project_id) REFERENCES projects(project_id),
#FOREIGN KEY(project_name) REFERENCES projects(project_name),
#FOREIGN KEY(project_owner) REFERENCES projects(project_owner),
#FOREIGN KEY(project_location) REFERENCES projects(project_location),
#FOREIGN KEY(cost) REFERENCES projects(cost));''')

conn.execute('''CREATE TABLE if not exists agreement
(agreement_code INTEGER PRIMARY KEY,
seller_id INTEGER,
land_id INTEGER,
agreement_date DATE DEFAULT (datetime('now','localtime')),
buy_code INTEGER NOT NULL,
number INTEGER NOT NULL,
FOREIGN KEY(seller_id) REFERENCES seller(seller_id),
FOREIGN KEY(land_id) REFERENCES land(land_id),
FOREIGN KEY(buy_code) REFERENCES procedure(buy_code));''')
