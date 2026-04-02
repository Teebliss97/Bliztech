// static/js/paystack_checkout.js
document.addEventListener('DOMContentLoaded', function () {
  var btn = document.getElementById('pay-btn');
  if (!btn) return;

  btn.addEventListener('click', function () {
    var emailInput = document.getElementById('customer-email');
    var email = emailInput ? emailInput.value.trim() : '';

    if (!email || !email.includes('@')) {
      emailInput.focus();
      emailInput.style.borderColor = '#ff4444';
      return;
    }

    emailInput.style.borderColor = '';
    btn.disabled = true;
    btn.textContent = 'Opening payment...';

    var handler = PaystackPop.setup({
      key: window.PAYSTACK_PUBLIC_KEY,
      email: email,
      amount: window.PAYSTACK_AMOUNT,
      currency: 'NGN',
      ref: 'BTA_' + new Date().getTime() + '_' + Math.floor(Math.random() * 1000000),
      label: 'Get Into Cybersecurity',
      onClose: function () {
        btn.disabled = false;
        btn.textContent = 'Pay ₦20,000 securely';
      },
      callback: function (response) {
        // Redirect to server-side verification
        window.location.href = window.PAYSTACK_CALLBACK_URL + '?reference=' + response.reference;
      }
    });

    handler.openIframe();
  });
});