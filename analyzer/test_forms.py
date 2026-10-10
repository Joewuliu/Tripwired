import pytest

from forms import classify, kinds_asked_for, sensitive_fields


def field(**attrs):
    return {"type": "text", "name": "", "id": "", "placeholder": "", "autocomplete": "", "ariaLabel": "", "label": "", **attrs}


@pytest.mark.parametrize("attrs,kind", [
    (dict(type="password"), "password"),
    (dict(name="new_password_confirm"), "password"),
    (dict(name="userPwd"), "password"),
    (dict(placeholder="Passcode"), "password"),
    (dict(autocomplete="current-password"), "password"),
    (dict(name="card_number"), "card"),
    (dict(id="cardNumber"), "card"),
    (dict(name="cc-num"), "card"),
    (dict(name="cvv"), "card"),
    (dict(name="cvc2"), "card"),
    (dict(placeholder="Expiry date"), "card"),
    (dict(name="expiration_month"), "card"),
    (dict(label="Security code"), "card"),
    (dict(autocomplete="cc-number"), "card"),
    (dict(autocomplete="section-pay cc-csc"), "card"),
    (dict(name="f1", label="Card number"), "card"),  # only the label says what it is
    (dict(id="ssn"), "ssn"),
    (dict(placeholder="Social Security number"), "ssn"),
    (dict(name="routing-number"), "bank"),
    (dict(name="account_number"), "bank"),
    (dict(ariaLabel="IBAN"), "bank"),
    (dict(name="userOtp"), "otp"),
    (dict(name="otp_code"), "otp"),
    (dict(label="One-time code"), "otp"),
    (dict(placeholder="Enter your one time passcode"), "otp"),
    (dict(placeholder="Verification code"), "otp"),
    (dict(autocomplete="one-time-code"), "otp"),
    (dict(name="pin"), "pin"),
    (dict(ariaLabel="Enter your PIN"), "pin"),
])
def test_sensitive_fields_are_recognised(attrs, kind):
    assert classify(field(**attrs)) == kind


@pytest.mark.parametrize("attrs", [
    dict(name="username"),
    dict(name="email", autocomplete="email"),
    dict(placeholder="Search"),
    dict(name="shipping_address"),
    dict(name="cardholder_name"),
    dict(name="account"),  # an account name, not an account number
    dict(id="classname"),  # contains "ssn"
    dict(name="spinner"),  # contains "pin"
    dict(name="mapping"),
    dict(name="pincode"),  # a postal code
    dict(placeholder="PIN code"),
    dict(name="passport_number"),
    dict(name="footprint"),
    dict(name="zip"),
    dict(type="radio", name="monthly", label="One time"),  # a donation frequency, seen on wikipedia.org
    dict(placeholder="One time gift amount"),
    dict(type="checkbox", name="save_card_number", label="Save card number"),
    dict(type="submit", name="update_password"),
])
def test_ordinary_fields_are_not_sensitive(attrs):
    assert classify(field(**attrs)) is None


def test_only_identifiers_are_kept_never_page_text():
    found = sensitive_fields([
        field(type="password", name="pw", id="p1", placeholder="Your bank password", label="Password"),
        field(name="username"),
    ])
    assert found == [{"kind": "password", "type": "password", "name": "pw", "id": "p1"}]


def test_kinds_are_listed_once_in_a_fixed_order():
    found = sensitive_fields([field(name="cvv"), field(type="password"), field(name="card_number"), field(name="otp")])
    assert kinds_asked_for(found) == ["password", "card", "otp"]
    assert kinds_asked_for([]) == []
