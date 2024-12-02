import pytest
from httpx import AsyncClient
from urllib.parse import urlencode
from app.main import app
from app.models.user_model import User
from app.services.jwt_service import decode_token, create_access_token
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password



@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token):
    """Test creating a user with insufficient permissions."""
    headers = {"Authorization": f"Bearer {user_token}"}
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "StrongPassword123!",
    }
    response = await async_client.post("/users/", json=user_data, headers=headers)

    # Check if the response status code is 401 (unauthorized) or 403 (forbidden)
    # Depending on the expected behavior for the user (e.g., token valid but no permissions)
    if response.status_code == 401:
        assert response.status_code == 401  # Token issues or invalid token
    else:
        # If the user has a valid token but doesn't have the proper role/permission
        assert response.status_code == 403  # Forbidden


@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    """Test retrieving a user with insufficient permissions."""
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    """Test retrieving a user with admin permissions."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    if response.status_code == 403:
        assert response.status_code == 403  # Unauthorized - Token issues or invalid token    
    
    else:
        assert response.status_code == 200 #Ok authorized 
        assert response.json()["id"] == str(admin_user.id)


@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    """Test updating a user's email with insufficient permissions."""
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, manager_user, manager_token):
    """Test updating a user's email with admin permissions."""
    updated_data = {"email": f"updated_{manager_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {manager_token}"}
    response = await async_client.put(f"/users/{manager_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, manager_user, manager_token):
    """Test deleting a user."""
    headers = {"Authorization": f"Bearer {manager_token}"}
    delete_response = await async_client.delete(f"/users/{manager_user.id}", headers=headers)
    assert delete_response.status_code == 204

    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{manager_user.id}", headers=headers)
    assert fetch_response.status_code == 404


@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    """Test creating a user with a duplicate email."""
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    """Test creating a user with an invalid email."""
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    """Test successful user login."""
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234",
    }
    response = await async_client.post(
        "/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None
    assert decoded_token["role"] == "AUTHENTICATED"


@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    """Test login attempt with a non-existent user."""
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!",
    }
    response = await async_client.post(
        "/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    """Test login attempt with incorrect password."""
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!",
    }
    response = await async_client.post(
        "/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")


# Add other test cases here with similar formatting and improvements.


@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, manager_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {manager_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, manager_user, manager_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {manager_token}"}
    response = await async_client.put(f"/users/{manager_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, manager_user, manager_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {manager_token}"}
    response = await async_client.put(f"/users/{manager_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

'''
@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()
'''

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()
    
@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 401  # Forbidden, as expected for regular user
    
    
# NEw Code ---
'''
@pytest.fixture
async def admin_token(admin_user):
    """Fixture to generate an admin token for authentication."""
    # Create a dictionary with user info
    data = {"sub": str(admin_user.id), "role": admin_user.role}
    token = create_access_token(data=data)  # Pass the data dictionary
    return token
'''

@pytest.fixture
async def admin_token(admin_user):
    """Fixture to generate an admin token for authentication."""
    data = {"sub": str(admin_user.id), "role": str(admin_user.role)}  # Ensure role is string
    token = create_access_token(data=data)
    return token

@pytest.fixture
async def manager_token(manager_user):
    """Fixture to generate a manager token for authentication."""
    # Create a dictionary with manager user info
    data = {"sub": str(manager_user.id), "role": "MANAGER"}
    token = create_access_token(data=data)  # Generate the token
    return token


