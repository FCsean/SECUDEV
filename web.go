package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	//	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"time"
)

const DatabaseURL = "file:database.sqlite?cache=shared&mode=rwc"

var cookies = sessions.NewCookieStore([]byte("813629774771309960518707211349999998"))

var templates *template.Template

func initTemplates() {
	files, _ := filepath.Glob("./templates/*.tmpl.html")
	templates = template.Must(template.ParseFiles(files...))
}

func renderPage(w http.ResponseWriter, template string, data interface{}) {
	err := templates.ExecuteTemplate(w, template+".tmpl.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func errorPage(w http.ResponseWriter, statusCode int) {
	errorMessage := fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode))
	http.Error(w, errorMessage, statusCode)
}

func homePage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isLoggedIn(r) {
			loginPage(w, r)
			return
		}

		userID, _ := getUserID(r)
		profile := getProfile(userID)
		if profile == nil {
			errorPage(w, http.StatusBadRequest)
			return
		}

		data := struct {
			Profile *UserProfile
			IsAdmin bool
		}{
			profile,
			isAdmin(r),
		}
		renderPage(w, "home", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if isLoggedIn(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		renderPage(w, "login", nil)
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")

		userID, ok := login(username, password)
		if !ok {
			http.Error(w, "Invalid username or password.", http.StatusBadRequest)
			return
		}

		session, _ := cookies.Get(r, "session")
		session.Values["user_id"] = userID
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func logoutPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		session, _ := cookies.Get(r, "session")
		delete(session.Values, "user_id")
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func registrationPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if isLoggedIn(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		renderPage(w, "register", nil)
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")

		accessLevel := r.FormValue("access_level")
		if accessLevel != "" && !isAdmin(r) {
			fmt.Fprintf(w, `
				<body style="background: black; text-align: center;">
					<video src="/images/gandalf.mp4" autoplay>You Shall Not Pass!</video>
				</body>
			`)
			return
		}
		admin := accessLevel == "admin"

		birthday, err := time.Parse("2006-01-02", r.FormValue("birthday"))
		if err != nil {
			errorPage(w, http.StatusBadRequest)
			return
		}

		profile := UserProfile{
			FirstName:  r.FormValue("first_name"),
			LastName:   r.FormValue("last_name"),
			Gender:     r.FormValue("gender"),
			Salutation: r.FormValue("salutation"),
			Birthday:   birthday,
			About:      r.FormValue("about"),
		}

		userID, err := register(username, password, admin, profile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if accessLevel == "" {
			session, _ := cookies.Get(r, "session")
			session.Values["user_id"] = userID
			session.Save(r, w)
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func adminRegistrationPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isAdmin(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		renderPage(w, "admin", nil)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

type UserProfile struct {
	FirstName  string
	LastName   string
	Gender     string
	Salutation string
	Birthday   time.Time
	About      string
}

var maleSalutations = stringSet(
	"Mr",
	"Sir",
	"Senior",
	"Count",
)

var femaleSalutations = stringSet(
	"Miss",
	"Ms",
	"Mrs",
	"Madame",
	"Majesty",
	"Seniora",
)

func stringSet(strings ...string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings {
		set[s] = true
	}
	return set
}

func age(birthday time.Time) int {
	return time.Now().Year() - birthday.Year()
}

func register(username, password string, admin bool, profile UserProfile) (int, error) {
	if !regexp.MustCompile("^[0-9A-Za-zñ ]{1,50}$").MatchString(profile.FirstName) {
		return 0, errors.New("Invalid first name.")
	}

	if !regexp.MustCompile("^[0-9A-Za-zñ ]{1,50}$").MatchString(profile.LastName) {
		return 0, errors.New("Invalid last name.")
	}

	switch profile.Gender {
	case "M":
		if !maleSalutations[profile.Salutation] {
			return 0, errors.New("Invalid salutation.")
		}
	case "F":
		if !femaleSalutations[profile.Salutation] {
			return 0, errors.New("Invalid salutation.")
		}
	default:
		return 0, errors.New("Invalid gender.")
	}

	if age(profile.Birthday) <= 18 {
		return 0, errors.New("Too young.")
	}

	if profile.About == "" {
		return 0, errors.New("Missing about.")
	}

	if !regexp.MustCompile("^[0-9A-Za-z_]{1,50}$").MatchString(username) {
		return 0, errors.New("Invalid username.")
	}

	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 0)

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}

	result, err := tx.Exec("INSERT INTO user_account (username, hashed_password, admin) VALUES (?, ?, ?)",
		username, hashedPassword, admin)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	userID, err := result.LastInsertId()
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	result, err = tx.Exec("INSERT INTO user_profile (account_id, first_name, last_name, "+
		"gender, salutation, birthday, about) VALUES (?, ?, ?, ?, ?, ?, ?)",
		userID, profile.FirstName, profile.LastName, profile.Gender,
		profile.Salutation, profile.Birthday, profile.About)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	tx.Commit()

	return int(userID), nil
}

func login(username, password string) (userID int, ok bool) {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return 0, false
	}
	defer db.Close()

	var hashedPassword string
	err = db.QueryRow("SELECT id, hashed_password FROM user_account WHERE username=?", username).Scan(&userID, &hashedPassword)
	if err != nil {
		return 0, false
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return userID, err == nil
}

func getUserID(req *http.Request) (userID int, ok bool) {
	session, _ := cookies.Get(req, "session")
	val := session.Values["user_id"]
	userID, ok = val.(int)
	return
}

func isLoggedIn(req *http.Request) bool {
	_, ok := getUserID(req)
	return ok
}

func isAdmin(req *http.Request) bool {
	userID, ok := getUserID(req)
	if !ok {
		return false
	}

	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return false
	}
	defer db.Close()

	err = db.QueryRow("SELECT id FROM user_account WHERE id=? AND admin=?", userID, true).Scan(&userID)
	return err == nil
}

func getProfile(userID int) *UserProfile {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return nil
	}
	defer db.Close()

	var profile UserProfile
	err = db.QueryRow("SELECT first_name, last_name, gender, salutation, birthday, about "+
		"FROM user_profile WHERE account_id=?", userID).Scan(&profile.FirstName, &profile.LastName,
		&profile.Gender, &profile.Salutation, &profile.Birthday, &profile.About)
	if err != nil {
		return nil
	}

	return &profile
}

func createDB() error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE user_account (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
					
			username VARCHAR(50) UNIQUE NOT NULL,
			hashed_password CHARACTER(60) NOT NULL,
			admin BOOLEAN NOT NULL DEFAULT FALSE
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE user_profile (
			account_id INTEGER PRIMARY KEY,
			
			first_name VARCHAR(50) NOT NULL,
			last_name VARCHAR(50) NOT NULL,
			gender CHARACTER(1) NOT NULL,
			salutation VARCHAR(20) NOT NULL,
			birthday DATE NOT NULL,
			about TEXT NOT NULL,
			
			FOREIGN KEY(account_id) REFERENCES user_account(id)
		)
	`)
	if err != nil {
		return err
	}

	_, err = register("admin", "admin", true, UserProfile{"Admin", "Admin", "M", "Mr", time.Date(1990, time.January, 1, 0, 0, 0, 0, time.UTC), "Admin"})
	
	return err
}

func main() {
	createDB()
	initTemplates()

	http.HandleFunc("/", homePage)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/logout", logoutPage)
	http.HandleFunc("/register", registrationPage)
	http.HandleFunc("/admin", adminRegistrationPage)

	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("./images"))))
	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("./styles"))))
	http.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("./scripts"))))

	http.ListenAndServe(":8080", context.ClearHandler(http.DefaultServeMux))
	// http.ListenAndServeTLS(":10443", "certificate/cert.pem", "certificate/key.pem", context.ClearHandler(http.DefaultServeMux))
}
