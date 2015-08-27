package main

import (
	"database/sql"
	"fmt"
	"github.com/gorilla/securecookie"
	_ "github.com/mattn/go-sqlite3"
	"html/template"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var insertUser, checkIfExists, selectUser, checkPassword, checkAdmin *sql.Stmt
var hashKey = []byte("very-secret")
var blockKey = []byte("12345secret54321")
var s = securecookie.New(hashKey, blockKey)

func loadPage(title string) (body []byte, err error) {
	body, err = ioutil.ReadFile(title)
	if err != nil {
		body = []byte("File Not Found")
	}
	return
}
func age(birthday time.Time) int {
	now := time.Now()
	years := now.Year() - birthday.Year()
	if now.YearDay() < birthday.YearDay() {
		years--
	}
	return years
}

func checkInSlice(value string, check []string) bool {
	for _, temp := range check {
		if value == temp {
			return true
		}
	}
	return false
}

func alphaNeumeric(value string) bool {
	matched, _ := regexp.MatchString("[A-Za-z0-9]*", value)
	return matched
}

func SetCookieHandler(w http.ResponseWriter, key, val string) {
	value := map[string]string{
		key: val,
	}
	if encoded, err := s.Encode("caseuno", value); err == nil {
		cookie := &http.Cookie{
			Name:  "cookie-name",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	} else {
		fmt.Println(err)
	}
}

func ReadCookieHandler(r *http.Request, key string) string {
	if cookie, err := r.Cookie("cookie-name"); err == nil {
		value := make(map[string]string)
		if err = s.Decode("caseuno", cookie.Value, &value); err == nil {
			return value[key]
		}
	} else {
		fmt.Println(err)
	}
	return ""
}

func registerAndAdd(w http.ResponseWriter, r *http.Request, admin bool) {
	fname := r.FormValue("fname")
	lname := r.FormValue("lname")
	gender := r.FormValue("sex")
	salutation := r.FormValue("salutation")

	username := r.FormValue("username")
	password := r.FormValue("password")
	about := r.FormValue("about")

	if fname == "" || lname == "" || gender == "" || salutation == "" || r.FormValue("bday") == "" || username == "" || password == "" {
		fmt.Fprintf(w, "Missing fields")
		return
	}

	bday, _ := time.Parse("2006-01-02", r.FormValue("bday"))
	if age(bday) <= 18 {
		fmt.Fprintf(w, "Too young")
		return
	}

	if gender == "male" {
		if !(checkInSlice(salutation, []string{"Mr.", "Sir", "Senior", "Count"})) {
			fmt.Fprintf(w, "Wrong salutation")
			return
		}
	} else if gender == "female" {
		if !(checkInSlice(salutation, []string{"Miss", "Ms.", "Mrs.", "Madame", "Majesty", "Senora"})) {
			fmt.Fprintf(w, "Wrong salutation")
			return
		}
	} else {
		fmt.Fprintf(w, "Wrong gender")
		return
	}

	if !alphaNeumeric(strings.Replace(fname, " ", "", -1)) || !alphaNeumeric(strings.Replace(lname, " ", "", -1)) {
		fmt.Fprintf(w, "No special characters allowed")
		return
	}

	if !alphaNeumeric(strings.Replace(username, "_", "", -1)) {
		fmt.Fprintf(w, "username must be alphaneumeric and underscores only")
		return
	}

	if len(fname) > 50 || len(lname) > 50 || len(username) > 50 {
		fmt.Fprintf(w, "Max char 50")
		return
	}
	var count int
	if checkIfExists.QueryRow(username).Scan(&count); count > 0 {
		fmt.Fprintf(w, "User already exists")
		return
	}
	insertUser.Exec(fname, lname, gender, salutation, fmt.Sprint(bday)[:10], username, password, about, admin)
	http.Redirect(w, r, "/login", 302)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		registerAndAdd(w, r, false)
	} else if r.Method == "GET" {
		body, err := loadPage("Register.html")
		if err != nil {
			http.Error(w, string(body), 404)
		} else {
			fmt.Fprintf(w, string(body))
		}
	}
}

func admin(w http.ResponseWriter, r *http.Request) {
	if ReadCookieHandler(r, "session") == "" {
		fmt.Fprintf(w, "Please log in.")
		return
	}
	var count int
	if checkIfExists.QueryRow(ReadCookieHandler(r, "session")).Scan(&count); count == 0 {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method == "POST" {
		adm, _ := strconv.ParseBool(r.FormValue("admin"))
		registerAndAdd(w, r, adm)
	} else if r.Method == "GET" {
		body, err := loadPage("Admin.html")
		if err != nil {
			http.Error(w, string(body), 404)
		} else {
			fmt.Fprintf(w, string(body))
		}
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "" || password == "" {
			fmt.Fprintf(w, "Missing username or password")
			return
		}
		rows, _ := checkPassword.Query(username, password)
		if !rows.Next() {
			fmt.Fprintf(w, "Invalid username or passwowrd")
			return
		}
		SetCookieHandler(w, "session", username)
		http.Redirect(w, r, "/user", 302)
	} else if r.Method == "GET" {
		body, err := loadPage("Login.html")
		if err != nil {
			http.Error(w, string(body), 404)
		} else {
			fmt.Fprintf(w, string(body))
		}
	}
}

func user(w http.ResponseWriter, r *http.Request) {
	body, err := loadPage("Landing.html")
	if err != nil {
		http.Error(w, string(body), 404)
	} else {
		if ReadCookieHandler(r, "session") == "" {
			fmt.Fprintf(w, "Please log in.")
			return
		}
		var count int
		if checkIfExists.QueryRow(ReadCookieHandler(r, "session")).Scan(&count); count == 0 {
			http.Redirect(w, r, "/login", 302)
			return
		}
		var username, fname, lname, gender, salutation, bday, about string
		var admin bool
		selectUser.QueryRow(ReadCookieHandler(r, "session")).Scan(&username, &fname, &lname, &gender, &salutation, &bday, &about, &admin)
		data := struct {
			Username   string
			Fname      string
			Lname      string
			Gender     string
			Salutation string
			Bday       string
			About      string
			Admin      bool
		}{
			username,
			fname,
			lname,
			gender,
			salutation,
			bday,
			about,
			admin,
		}
		t, _ := template.ParseFiles("Landing.html")
		err := t.Execute(w, data)
		fmt.Println(err)
	}
}

func main() {
	db, err := sql.Open("sqlite3", "sample.db")
	if err != nil {
		fmt.Printf("%v", err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS USERS (ID INTEGER PRIMARY KEY AUTOINCREMENT, fname text not null, lname text not null, gender text not null, salutation text not null, bday text not null, username text not null, password text not null, about text not null, admin boolean not null)")
	fmt.Println(err)
	insertUser, err = db.Prepare("INSERT INTO USERS (fname, lname, gender, salutation, bday, username, password, about, admin)  VALUES (?,?,?,?,?,?,?,?,?) ")
	fmt.Println(err)
	checkPassword, err = db.Prepare("SELECT * FROM USERS WHERE lower(username) = lower(?) and password = ?")
	fmt.Println(err)
	checkAdmin, err = db.Prepare("SELECT admin FROM USERS WHERE username = ?")
	fmt.Println(err)
	selectUser, err = db.Prepare("SELECT username, fname, lname, gender, salutation, bday, about, admin FROM USERS WHERE lower(username) = lower(?)")
	fmt.Println(err)
	checkIfExists, err = db.Prepare("SELECT COUNT(*) FROM USERS WHERE lower(username) = lower(?)")
	fmt.Println(err)
	defer db.Close()

	http.HandleFunc("/register", register)
	http.HandleFunc("/admin", admin) //send user data
	http.HandleFunc("/login", login)
	http.HandleFunc("/user", user)

	http.ListenAndServe(":8080", nil)
}
