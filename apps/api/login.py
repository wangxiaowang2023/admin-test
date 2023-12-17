import functools
import hashlib
import inspect

import requests
from logger import logger

# ```
# curl -X 'GET' \
#   'http://0.0.0.0:8000/api/captcha/' \
#   -H 'accept: application/json' \
#   -H 'X-CSRFToken: FPdQTOspHYJQLueBHFtgFsC3K2CEobBKzb2lj4iAphv1rPuol6Oexa7QdhgkREwS'
# ```
base_url = "http://0.0.0.0:8000/api/"


def log_method(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        logger.info(f"{func.__name__} {result.url} code={result.status_code},\n{func.__name__} response {result.json()}")
        # logger.info(f"{inspect.stack()[0][3]},{result.url}")
        # logger.info(f"{inspect.stack()[0][3]},{result.json()}")
        return result

    return wrapper


class Login(object):
    @staticmethod
    def captcha():
        headers = {'accept': 'application/json'}
        res = requests.get(url=base_url + "captcha/", headers=headers)
        logger.info(f"{inspect.stack()[0][3]},{res.status_code}")
        logger.info(f"{inspect.stack()[0][3]},{res.url}")
        # logger.info(f"{inspect.stack()[0][3]},{res.json()}")
        return res.json()['data']['key']

    @staticmethod
    @log_method
    def login_in(username, pwd, captcha_key):
        # pwd = "admin123456"
        pwd_h5 = hashlib.md5(pwd.encode(encoding='utf-8')).hexdigest()
        headers = {'accept': 'application/json'}
        login_data = {
            "captcha": "123456",
            "username": username,
            "password": pwd_h5,
            "captchaKey": captcha_key
        }
        res = requests.post(url=base_url + "login/", json=login_data, headers=headers)
        # logger.info(f"{inspect.stack()[0][3]},{res.status_code}")
        # logger.info(f"{inspect.stack()[0][3]},{res.url}")
        # logger.info(f"{inspect.stack()[0][3]},{res.json()}")
        return res


class System(object):
    @staticmethod
    @log_method
    def create_user(username, pwd, token):
        pwd_h5 = hashlib.md5(pwd.encode(encoding='utf-8')).hexdigest()
        headers = {'accept': 'application/json', 'Content-Type': 'application/json', "Authorization": "JWT " + token}
        login_data = {"username": username, "password": pwd_h5, "name": "test005",
                      "dept": 3, "role": [1, 2], "mobile": "13888888888", "email": "888@163.com", "gender": 1,
                      "user_type": 0, "is_active": "true", "description": "test"}
        res = requests.post(url=base_url + "system/user/", json=login_data, headers=headers)
        return res.json()


if __name__ == '__main__':
    l = Login()
    s = System()
    r = l.captcha()
    # print(r)
    # g = l.login_in(username="superadmin", pwd="admin123456", captcha_key=r)
    # print(g)
    # token = g['data']['access']
    # c=s.create_user(username="test007", pwd="admin123456", token=token)
    l2 = l.login_in(username="test007", pwd="admin123456", captcha_key=r)
    print(l2)
