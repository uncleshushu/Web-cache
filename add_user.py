import db_manager

DB_PATH = 'proxy_db.db'

dbManager = db_manager.DBManager(DB_PATH)

username = input("username: ")
password = input("password: ")

dbManager.add_user(username, password)

print('test DBManager.user_auth()...')
assert dbManager.user_auth(username, password)
print('pass')
print()

print('User added.')