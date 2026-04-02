import os
import hmac
import hashlib
import json
import requests
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from app.extensions import db
from app.models import User, CourseAccess

paystack_bp = Blueprint('paystack', __name__)

PAYSTACK_SECRET_KEY = os.environ.get('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = os.environ.get('PAYSTACK_PUBLIC_KEY')
COURSE_PRICE_NGN = 20000
COURSE_PRICE_KOBO = COURSE_PRICE_NGN * 100  # Paystack uses kobo (100 kobo = 1 naira)


def grant_course_access_paystack(email):
    """
    Grant paid course access to a user by email.
    Sets both has_course_access flag and creates CourseAccess record.
    Creates a stub user if they haven't registered yet.
    """
    email = email.lower().strip()
    user = User.query.filter_by(email=email).first()

    if not user:
        from werkzeug.security import generate_password_hash
        user = User(
            email=email,
            password_hash=generate_password_hash(os.urandom(32).hex()),
            has_course_access=True,
        )
        db.session.add(user)
        db.session.flush()
    else:
        user.has_course_access = True

    existing = CourseAccess.query.filter_by(user_id=user.id).first()
    if not existing:
        access = CourseAccess(
            user_id=user.id,
            granted_at=datetime.utcnow(),
            granted_by='paystack_webhook',
            gumroad_sale_id=None,
        )
        db.session.add(access)

    db.session.commit()
    return True


@paystack_bp.route('/pay/ng')
def pay_ng():
    return render_template(
        'pay_ng.html',
        public_key=PAYSTACK_PUBLIC_KEY,
        price_naira=COURSE_PRICE_NGN,
        price_kobo=COURSE_PRICE_KOBO,
    )


@paystack_bp.route('/pay/ng/verify')
def pay_ng_verify():
    reference = request.args.get('reference')
    if not reference:
        flash('No payment reference found.', 'error')
        return redirect(url_for('paystack.pay_ng'))

    headers = {'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}'}
    try:
        resp = requests.get(
            f'https://api.paystack.co/transaction/verify/{reference}',
            headers=headers,
            timeout=15,
        )
    except requests.RequestException:
        flash('Could not reach payment server. Please contact support.', 'error')
        return redirect(url_for('paystack.pay_ng'))

    if resp.status_code != 200:
        flash('Could not verify payment. Please contact support.', 'error')
        return redirect(url_for('paystack.pay_ng'))

    data = resp.json()

    if (
        data.get('data', {}).get('status') == 'success'
        and data['data'].get('amount', 0) >= COURSE_PRICE_KOBO
    ):
        email = data['data']['customer']['email']
        grant_course_access_paystack(email)
        return redirect(url_for('paystack.pay_ng_success', email=email))
    else:
        flash('Payment was not completed. Please try again.', 'error')
        return redirect(url_for('paystack.pay_ng'))


@paystack_bp.route('/pay/ng/webhook', methods=['POST'])
def pay_ng_webhook():
    paystack_signature = request.headers.get('X-Paystack-Signature', '')
    payload = request.get_data()

    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode('utf-8'),
        payload,
        hashlib.sha512,
    ).hexdigest()

    if not hmac.compare_digest(expected, paystack_signature):
        return jsonify({'status': 'invalid signature'}), 400

    try:
        event = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return jsonify({'status': 'bad payload'}), 400

    if event.get('event') == 'charge.success':
        data = event.get('data', {})
        if data.get('status') == 'success' and data.get('amount', 0) >= COURSE_PRICE_KOBO:
            email = data.get('customer', {}).get('email', '')
            if email:
                grant_course_access_paystack(email)

    return jsonify({'status': 'ok'}), 200


@paystack_bp.route('/pay/ng/success')
def pay_ng_success():
    email = request.args.get('email', '')
    return render_template('pay_ng_success.html', email=email)

@paystack_bp.route('/pay/choose')
def pay_choose():
    return render_template('pay_choose.html')