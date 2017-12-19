#!/usr/bin/env python3

import os

import db_manager

TEST_DB_PATH = 'test.db'

TEST_USER = 'admin'
TEST_PASSWD = 'password'
TEST_RULE_PATH = db_manager.RULE_PATH_PREFIX + TEST_USER + '.rule'

dbManager = db_manager.DBManager(TEST_DB_PATH)

def init_db():
    '''
    initialize the database for test
    '''
    with open("init.sql") as init_file:
        init_script = init_file.read()

    
    dbManager.cursor.executescript(init_script)
    dbManager.conn.commit()


def clear():
    dbManager.conn.close()
    os.remove(TEST_DB_PATH)
    os.remove(TEST_RULE_PATH)


def test_add_user():
    print('test DBManager.add_user()...')
    dbManager.add_user(TEST_USER, TEST_PASSWD)
    print('pass')
    print()


def test_user_auth():
    print('test DBManager.user_auth()...')
    assert dbManager.user_auth(TEST_USER, TEST_PASSWD)
    print('pass')
    print()


def test_get_rules():
    print('test DBManager.get_rules()...')

    print('when there is no rule...')
    rules = dbManager.get_rules(TEST_USER)
    assert rules is None
    print('rules: {}'.format(rules))

    rules = {"cc.scu.edu.cn":"swjx.scu.edu.cn"}
    db_manager.dump_rules(rules, TEST_RULE_PATH)
    dbManager.cursor.execute('UPDATE users SET rule_path=? WHERE name=?', (TEST_RULE_PATH, TEST_USER))
    dbManager.conn.commit()
    print("after a rule is inserted...")
    rules_got = dbManager.get_rules(TEST_USER)
    assert rules_got == rules 
    print('rules: {}'.format(rules_got))

    # do some cleaning
    os.remove(TEST_RULE_PATH)
    dbManager.cursor.execute('UPDATE users SET rule_path=? WHERE name=?', (None, TEST_USER))
    dbManager.conn.commit()
    print('temporary rules cleared')

    print('pass')
    print()


def test_add_rules():
    print('test DBManager.add_rules()...')
    dbManager.add_rules(TEST_USER, {'www.baidu.com':'www.bing.com', 'www.sina.com':''})
    dbManager.add_rules(TEST_USER, {'www.zhihu.com':'www.douban.com'})
    rules = dbManager.get_rules(TEST_USER)
    print('rules after add_rules(): {}'.format(rules))

    print('pass')
    print()


def test_all():
    try:
        init_db()
        test_add_user()
        test_user_auth()
        test_get_rules()
        test_add_rules()
    finally:
        clear()


if __name__ == '__main__':
    test_all()