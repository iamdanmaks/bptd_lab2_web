import json

from flask import jsonify
from flask import render_template
from flask import request

from app import app
from app import keys
from app import user_data
from app import messages
from app.utils import check_password
from app.utils import decrypt
from app.utils import encrypt
from app.utils import generate_rsa_key
from app.utils import key2pubpkcs
from app.utils import key2pripkcs
from app.utils import pkcs2key
from app.utils import search_for_user
from app.utils import check_password


# генерируем ключи сервера перед первым запросом
@app.before_first_request
def before_first_request_func():
    with open('public.pem', 'r') as read_file:
        keys[0] = pkcs2key(read_file.read())
    
    with open('private.pem', 'r') as read_file:
        keys[1] = pkcs2key(read_file.read())


# генерируем ключи для сессии
@app.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    print('\n\n\n',keys,'\n\n\n')
    if request.method == 'POST':
        # переводим публичный ключ клиента в объект rsa
        client_public = pkcs2key(request.json.get('public'))
        # генерируем ключи сессии со стороны сервера
        session_key = generate_rsa_key()
        # создаём временный идентификатор для сессии
        temp_login = str(len(user_data))

        # сохраняем приватный ключ сессии со стороны сервера
        #  и публичный ключ клиента
        user_data[temp_login] = {
            "password": "",
            "session_server_private": session_key,
            "session_client_public": client_public
        }

        # возвращаем публичный ключ сервера, публичный ключ сессии,
        # зашифрованый публичным ключем клиента временный идентификатор
        return jsonify({
            "public_server": key2pubpkcs(keys[0]),
            "public_session": key2pubpkcs(session_key),
            "temp_login": encrypt(temp_login, client_public)
        })


@app.route('/api/login', methods=['POST'])
def login():
    if request.method == 'POST':
        # расшифровали временный идентификатор 
        # приватным ключем сервера
        temp_login = decrypt(
            request.json.get('temp_login'),
            keys[1]
        )
        temp_user = user_data[temp_login]
        
        # расшифровали логин и пароль 
        # приватным ключем сессии
        username = decrypt(
                request.json.get('username'),
                temp_user.get('session_server_private')
            )
        password = decrypt(
                request.json.get('passw'),
                temp_user.get('session_server_private')
            )

        # ищем аккаунт
        account = search_for_user(
            user_data, 
            username
        )

        # если существует
        if account:
            # проверяем пароль
            passw = check_password(
                account, 
                password
            )
            
            # если правильный
            if passw:
                # переносим данные из временной сессии в ту, 
                # что привязана к пользователю
                user_data[username]['session_server_private'] =\
                    temp_user['session_server_private']
                
                user_data[username]['session_client_public'] =\
                    temp_user['session_client_public']
                
                # удаляем временную
                del user_data[temp_login]

                # возвращаем логин и сообщение
                # зашифрованые публичным ключем клиента
                return jsonify({
                    "response": True,
                    "message": encrypt(
                        "Logged in",
                        account['session_client_public']
                    ),
                    "username": encrypt(
                        username,
                        account['session_client_public']
                    )
                })
            # если неправильно
            else:
                # возвращаем сообщение
                # зашифрованые публичным ключем клиента
                return jsonify({
                    "response": False,
                    "message": encrypt(
                        "Wrong password",
                        temp_user['session_client_public']
                    )
                })
        # если не существует
        else:
            # создаём аккаунт
            user_data[username] = {}

            # шифруем пароль ключем сервера
            user_data[username]['password'] =\
                encrypt(
                    password, 
                    keys[0]
                )
            
            # сохраняем ключи
            user_data[username]['session_server_private'] =\
                 temp_user['session_server_private']
            
            user_data[username]['session_client_public'] =\
                 temp_user['session_client_public']
            
            # удаляем временную сессию
            del user_data[temp_login]

            return jsonify({
                "response": False,
                "message": encrypt(
                    'Account created',
                    user_data[username]['session_client_public']
                ),
                "username": encrypt(
                    username,
                    user_data[username]['session_client_public']
                )
            })


@app.route('/api/message', methods=['POST'])
def message():
    if request.method == 'POST':
        # ищем пользователя по имени
        username = decrypt(
            request.json.get('username'),
            keys[1]
        )
        user = search_for_user(user_data, username)

        # расшифровываем сообщение и шифруем другим ключем
        # шифруем публичным ключем сервера, 
        # чтоб доступ к чату был у всех пользователей
        messages.append({
            'user': encrypt(username, keys[0]),
            'content': encrypt(decrypt(
                    request.json.get('message'), 
                    user['session_server_private']
                ), keys[0])
        })

        # возвращаем сообщения 
        # зашифрованые публичным ключем клиента
        response = {
            "messages": [
                {
                    "user": encrypt(
                        decrypt(m['user'], keys[1]),
                        user['session_client_public']
                    ),
                    "content": encrypt(
                        decrypt(m['content'], keys[1]),
                        user['session_client_public']
                    )
                } for m in messages
            ]
        }

        return jsonify(response)


# post запрос используется из-за того, что 
# в url строке не поместится зашифрованное сообщение
@app.route('/api/messages', methods=['POST'])
def user_messages():
    # ищем пользователя
    username = decrypt(
        request.json.get('username'),
        keys[1]
    )
    user = search_for_user(user_data, username)

    # возвращаем сообщения 
    # зашифрованые публичным ключем клиента
    response = {
        "messages": [
            {
                "user": encrypt(
                    decrypt(m['user'], keys[1]),
                    user['session_client_public']
                ),
                "content": encrypt(
                    decrypt(m['content'], keys[1]),
                    user['session_client_public']
                )
            } for m in messages
        ]
    }

    return jsonify(response)
