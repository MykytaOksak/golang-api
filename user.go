package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

type User struct {
	Email          string
	PasswordDigest string
	FavoriteCake   string
}

type UserRepository interface {
	Add(string, User) error
	Get(string) (User, error)
	Update(string, User) error
	Delete(string) (User, error)
}

type UserService struct {
	repository UserRepository
}
type UserRegisterParams struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	FavoriteCake string `json:"favorite_cake"`
}

type ChangeUserParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	NewCake  string `json:"new_cake"`
	NewPass  string `json:"new_pass"`
	NewEmail string `json:"new_email"`
}

func validateCake(cake string) error {
	if len(cake) == 0 {
		err := errors.New("favorite cake is empty")
		return err
	}

	match, _ := regexp.MatchString("^[a-zA-Z]+$", cake)
	if !match {
		err := errors.New("favorite cake is only alphabetic")
		return err
	}
	return nil
}

func validateEmail(email string) error {
	match, _ := regexp.MatchString("^[^ ]+@[^ ]+[.][^ ]+$", email)
	if !match && email != "hackademy" {
		err := errors.New("email is not valid")
		return err
	}
	return nil
}

func validatePassword(pass string) error {
	if len(pass) < 8 {
		err := errors.New("password too short (at least 8 symbols)")
		return err
	}
	return nil
}

func validateRegisterParams(p *UserRegisterParams) error {
	if err := validatePassword(p.Password); err != nil {
		return err
	}

	if err := validateEmail(p.Email); err != nil {
		return err
	}

	if err := validateCake(p.FavoriteCake); err != nil {
		return err
	}

	return nil
}
func (u *UserService) Register(w http.ResponseWriter, r *http.Request) {
	params := &UserRegisterParams{}

	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))

	newUser := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
	}

	err = u.repository.Add(params.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered"))
}

func handleError(err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	w.Write([]byte(err.Error()))
}

func (u *UserService) ShowMyCake(w http.ResponseWriter, r *http.Request) {
	params := &JWTParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid login params"), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(user.FavoriteCake))
}

func (u *UserService) ChangeCake(w http.ResponseWriter, r *http.Request) {
	params := &ChangeUserParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid login params"), w)
		return
	}
	if err := validateCake(params.NewCake); err != nil {
		handleError(err, w)
		return
	}

	newUser := User{params.Email, user.PasswordDigest, params.NewCake}
	u.repository.Update(params.Email, newUser)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("cake successful changed"))
}

func (u *UserService) ChangeEmail(w http.ResponseWriter, r *http.Request) {
	params := &ChangeUserParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid login params"), w)
		return
	}
	if err := validateEmail(params.NewEmail); err != nil {
		handleError(err, w)
		return
	}

	newUser := User{params.NewEmail, user.PasswordDigest, user.FavoriteCake}
	u.repository.Delete(params.Email)
	u.repository.Add(params.NewEmail, newUser)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("email successful changed"))
}

func (u *UserService) ChangePassword(w http.ResponseWriter, r *http.Request) {
	params := &ChangeUserParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid login params"), w)
		return
	}
	if err := validatePassword(params.NewPass); err != nil {
		handleError(err, w)
		return
	}
	newPasswordDigest := md5.New().Sum([]byte(params.NewPass))

	newUser := User{params.Email, string(newPasswordDigest), user.FavoriteCake}
	u.repository.Update(params.Email, newUser)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("password successful changed"))
}
