from triage.html_hygiene import contains_hidden_content, strip_hidden_elements


def test_detects_white_on_white():
    html = '<p style="color:#ffffff;background-color:#ffffff">secret</p><p>vizibil</p>'
    assert contains_hidden_content(html) is True
    cleaned = strip_hidden_elements(html)
    assert "secret" not in cleaned
    assert "vizibil" in cleaned


def test_detects_tiny_font():
    html = '<span style="font-size:1px">ascuns</span> text normal'
    assert contains_hidden_content(html) is True
    assert "ascuns" not in strip_hidden_elements(html)


def test_plain_text_passes_through():
    assert strip_hidden_elements("doar text simplu") == "doar text simplu"
    assert contains_hidden_content("doar text simplu") is False