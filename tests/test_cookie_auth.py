"""Browser cookie authentication regression tests."""


def test_same_site_cookie_authenticates_protected_route(client, auth_token):
    client.cookies.set("homeradar_token", auth_token)
    response = client.post("/trust/recalculate")
    assert response.status_code == 200


def test_invalid_cookie_is_rejected_by_route_guard(client):
    client.cookies.set("homeradar_token", "invalid")
    response = client.post("/trust/recalculate")
    assert response.status_code == 401
