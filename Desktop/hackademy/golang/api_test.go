package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type parsedResponse struct {
	status int
	body   []byte
}

func createRequester(t *testing.T) func(req *http.Request, err error) parsedResponse {
	return func(req *http.Request, err error) parsedResponse {
		if err != nil {

			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		resp, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		return parsedResponse{res.StatusCode, resp}
	}
}
func prepareParams(t *testing.T, params map[string]interface{}) io.Reader {

	body, err := json.Marshal(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	return bytes.NewBuffer(body)
}
func newTestUserService() *UserService {
	return &UserService{
		repository: NewInMemoryUserStorage(),
	}
}

func assertStatus(t *testing.T, expected int, r parsedResponse) {
	if r.status != expected {
		t.Errorf("Unexpected response status. Expected: %d, actual: %d", expected, r.status)
	}
}
func assertBody(t *testing.T, expected string, r parsedResponse) {
	actual := string(r.body)
	if actual != expected {
		t.Errorf("Unexpected response body. Expected: %s, actual: %s", expected, actual)
	}
}
func assertChanging(t *testing.T, expected string, actual string) {
	if actual != expected {
		t.Errorf("Unexpected changed value. Expected: %s, actual: %s", expected, actual)
	}
}
func Test(t *testing.T) {
	doRequest := createRequester(t)
	u := newTestUserService()

	j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
	if err != nil {
		t.FailNow()
	}

	var JWTtoken string

	t.Run("user does not exist", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "there is no such user", resp)
	})
	t.Run("registered", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 201, resp)
		assertBody(t, "registered", resp)
	})
	t.Run("short password", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "some",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "password too short (at least 8 symbols)", resp)
	})
	t.Run("invalid email", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "tes.wrong.email",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "email is not valid", resp)
	})
	t.Run("login with empty cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "favorite cake is empty", resp)
	})
	t.Run("register cake with nums", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "111",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "favorite cake is only alphabetic", resp)
	})
	t.Run("login with wrong password", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "wrongpass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))

		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})
	t.Run("login with right password", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		JWTtoken = string(resp.body)
		assertStatus(t, 200, resp)
	})
	t.Run("get cake problem", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.repository, getCakeHandler)))
		defer ts.Close()
		resp := doRequest(http.NewRequest(http.MethodGet, ts.URL, nil))
		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)

	})
	t.Run("no cake problem", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.repository, getCakeHandler)))
		defer ts.Close()
		cakeReq, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
		cakeReq.Header.Set("Authorization", "Bearer "+JWTtoken)
		resp := doRequest(cakeReq, nil)
		assertStatus(t, 200, resp)
		assertBody(t, "cheesecake", resp)
	})
	t.Run("get my cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ShowMyCake))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "cheesecake", resp)
	})
	t.Run("change cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeCake))
		defer ts.Close()
		params := map[string]interface{}{
			"email":     "test@mail.com",
			"password":  "somepass",
			"new_cake":  "anothercake",
			"new_pass":  "",
			"new_email": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "cake successful changed", resp)
		user, _ := u.repository.Get("test@mail.com")
		assertChanging(t, "anothercake", user.FavoriteCake)
	})
	t.Run("get my cake after changing", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ShowMyCake))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "anothercake", resp)
	})
	t.Run("change email", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeEmail))
		defer ts.Close()
		params := map[string]interface{}{
			"email":     "test@mail.com",
			"password":  "somepass",
			"new_cake":  "",
			"new_pass":  "",
			"new_email": "test2@mail.com",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))

		assertStatus(t, 200, resp)
		assertBody(t, "email successful changed", resp)
		user, _ := u.repository.Get("test2@mail.com")
		assertChanging(t, "test2@mail.com", user.Email)
	})
	/*
	t.Run("login after new email", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test2@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
	})*/
	t.Run("change password", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangePassword))
		defer ts.Close()
		params := map[string]interface{}{
			"email":     "test2@mail.com",
			"password":  "somepass",
			"new_cake":  "",
			"new_pass":  "newpasss",
			"new_email": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))

		assertStatus(t, 200, resp)
		assertBody(t, "password successful changed", resp)
	})
	t.Run("login after new values", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test2@mail.com",
			"password": "newpasss",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
	})
}
