from app.security_rules import scan_code


def test_secret_detection():

    code = """
API_KEY = 'super-secret-value'
"""

    findings = scan_code(
        code,
        "test.py"
    )

    assert any(
        x["rule_id"] == "SEC001"
        for x in findings
    )


def test_eval_detection():

    code = """
result = eval(user_input)
"""

    findings = scan_code(
        code,
        "test.py"
    )

    assert any(
        x["rule_id"] == "SEC002"
        for x in findings
    )