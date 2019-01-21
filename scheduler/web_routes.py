from scheduler import app, db, auth
from flask import render_template, request, session, redirect, url_for, abort, flash
from bson.objectid import ObjectId

@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']

        user = db.users.find_one({'username': username})
        if user is None:
            #abort(400)
            flash('Неверный логин или пароль:/', 'failure')
            return redirect(url_for('main'))

        salt = user['salt']
        salted_password = auth.hash_password_and_salt(password, salt)
        if not auth.check_password(password, salt, salted_password):
            flash('Неверный логин или пароль:/', 'failure')
            return redirect(url_for('main'))
        user_id = str(user['_id'])
        session['token'] = auth.gen_signed_token(user_id)
        return redirect(url_for('main'))


    return render_template('auth.html', title='Авторизация')

@app.route('/')
def main():
    if 'token' not in session:
        return redirect('authorize')

    user_id = auth.check_token(session['token'])
    if user_id is None:
        return redirect('authorize')

    user = db.users.find_one({'_id': ObjectId(user_id)})

    schedule = db.schedules.find_one({'_id': ObjectId(user['subscribed_to'])})

    return render_template('main.html', user=user, schedule=schedule)
