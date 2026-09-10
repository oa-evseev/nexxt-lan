from nexxt.rtc_signaling import (
    classify_signaling_message,
    lifecycle_response_is_accepted,
)


def test_classification_and_preconnect_activation_response_policy():
    response = {
        "header": {"type": "activate_resp"},
        "msg": {"handle": 1, "seq": 1, "error": 0},
    }
    assert classify_signaling_message(response) == (
        "activate_resp",
        response["header"],
        response["msg"],
    )
    assert lifecycle_response_is_accepted(response, expected_type="activate_resp")
    response["msg"]["error"] = -25
    assert not lifecycle_response_is_accepted(response, expected_type="activate_resp")
    assert classify_signaling_message({"header": {"type": "answer"}, "msg": []}) is None
