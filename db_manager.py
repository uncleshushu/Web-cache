#!/usr/bin/env python3

'''
'''
import os
import base64
import sqlite3
import hmac
import json

SECRET_KEY = b'it is a secret'

RULE_PATH_PREFIX = 'rules/'

def load_rules(rule_path):
    with open(rule_path) as rule_file:
        # TODO: decode a file-like object as a `rules` object
        rules = json.load(rule_file)

    return rules

def dump_rules(rules, rule_path):
    with open(rule_path, 'w+') as rule_file:
        # TODO: encode a `rules` object and save it
        json.dump(rules, rule_file)


class DBManager:
    def __init__(self, db='proxy_db.db'):
        self.conn = sqlite3.connect(db)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        

    def add_user(self, username, password, rule_path=''):
        if isinstance(password, str):
            password = password.encode()

        assert isinstance(password, bytes)
        hashed_password = hmac.HMAC(password, SECRET_KEY).digest()

        self.cursor.execute('INSERT INTO users VALUES (?, ?, ?)', (username, hashed_password, rule_path))
        self.conn.commit()


    def user_auth(self, given_name, given_passwd):
        if not given_name:
            # raise ValueError('username must not be empty')
            return False

        # print('given_name for auth: ', given_name)
        self.cursor.execute('SELECT passwd_hash FROM users WHERE name=?', (given_name,))
        row = self.cursor.fetchone()
        if not row:
            # no such user
            # raise ValueError('No such user')
            # print('No such user with given_name "%s"' %(given_name) )
            return False

        passwd_hash = row['passwd_hash']
        if not passwd_hash:
            # print("password not required for this user.")
            return True
        
        if not given_passwd:
            given_passwd = b''

        # print('given_passwd for auth: ', given_passwd)
        if isinstance(given_passwd, str):
            given_passwd = given_passwd.encode()
        assert isinstance(given_passwd, bytes)

        return hmac.compare_digest(hmac.HMAC(given_passwd, SECRET_KEY).digest(), passwd_hash)     


    def add_rules(self, username, new_rules):
        self.cursor.execute('SELECT rule_path FROM users WHERE name=?', (username,))
        row = self.cursor.fetchone()
        if not row:
            # no such user
            raise ValueError('No such user.')

        rule_path = row['rule_path']
        if not rule_path:
            # create the rule file
            rule_path = RULE_PATH_PREFIX + username + '.rule'
            self.cursor.execute('UPDATE users SET rule_path=? WHERE name=?', (rule_path, username))
            self.conn.commit()
            # create the file and write an empty brace
            dump_rules({}, rule_path)

            # print('rule_file after creation: {}'.format(open(rule_path).read()))

        # print('rule_file before add_rule(): {}'.format(open(rule_path).read()))
        rules = load_rules(rule_path)
        # print('rules exists: {}'.format(rules))
        # merge the rules
        rules.update(new_rules)
        # print('rules after update: {}'.format(rules))
        # save it to file
        dump_rules(rules, rule_path)
    
        # print('rule file after add_rule(): {}'.format(open(rule_path).read()))


    def delete_rules(self, username, real_urls):
        self.cursor.execute('SELECT rule_path FROM users WHERE name=?', username)
        record = self.cursor.fetchone()
        if not record:
            # no such user
            raise ValueError('No such user.')

        rule_path = record['rule_path']
        if not rule_path:
            raise ValueError('No rules for this user.')
        
        with open(rule_path, 'r+') as rule_file:
            # TODO: decode the file as json

            pass


    def get_rules(self, username):
        '''
        return rules contained in the rule_file of the user
        '''
        self.cursor.execute('SELECT rule_path FROM users WHERE name=?', (username,))
        row = self.cursor.fetchone()
        if not row:
            # no such user
            raise ValueError('No such user')
        rule_path = row['rule_path']
        if rule_path:
            rules = load_rules(rule_path)
            return rules
        else:
            # There are no rules for the user.
            return None


    def modify_rule(self, username, in_url, fake_url):
        pass



    def query_cache(self, host_port, path):
        pass
