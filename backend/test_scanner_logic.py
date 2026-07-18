from scanner_logic import calculate_score, is_valid_url_structure, check_https, check_hyphens


def test_https_missing_flags_risk():
    points, reason = check_https("http://fake-bank-login.com")
    assert points == 15
    assert reason is not None


def test_https_present_no_penalty():
    points, reason = check_https("https://www.royalbank.com")
    assert points == 0
    assert reason is None


def test_hyphen_threshold_catches_three():
    points, reason = check_hyphens("https://secure-login-verify-now.com")
    assert points == 10


def test_valid_url_structure_accepts_real_url():
    assert is_valid_url_structure("https://www.google.com") == True


def test_valid_url_structure_rejects_garbage():
    assert is_valid_url_structure("banana") == False


def test_valid_url_structure_rejects_empty():
    assert is_valid_url_structure("   ") == False


def test_calculate_score_flags_known_phishing_pattern():
    result = calculate_score("https://ucalgary-student-report-verify.com")
    assert result["score"] > 0
    assert result["risk_level"] in ["Low", "Medium", "High"]
    assert len(result["reasons"]) > 0


def test_calculate_score_safe_url_stays_low():
    result = calculate_score("https://www.ucalgary.ca")
    assert result["risk_level"] == "Low"


def test_calculate_score_caps_at_100():
    result = calculate_score("http://verify-urgent-account-login-update-confirm-security@rbc-cibc-td-fake-secure-site.com")
    assert result["score"] <= 100