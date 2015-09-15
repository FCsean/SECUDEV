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
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const DatabaseURL = "file:database.sqlite?cache=shared&mode=rwc"

var cookies = sessions.NewCookieStore([]byte("813629774771309960518707211349999998"))

var templates *template.Template

var messagesPerPage = 10

func initTemplates() {
	templates = template.Must(template.New("").Funcs(template.FuncMap{
		"showDate":     func(date time.Time) string { return date.Format("Jan 2, 2006") },
		"showDateTime": func(date time.Time) string { return date.Format(time.RFC850) },
		"showISODate":  func(date time.Time) string { return date.Format("2006-01-02") },
		"minus":        func(a, b int) int { return a - b },
		"add":          func(a, b int) int { return a + b },
		"boldItalics": func(s string) template.HTML {
			s = template.HTMLEscapeString(s)
			imageTags := regexp.MustCompile("&lt;(img\\s+src=)&#34;(.*)&#34;&gt;")
			s = imageTags.ReplaceAllString(s, "<$1\"$2\" style=\"max-width:570px;\">")
			unescapeTags := regexp.MustCompile("&lt;(/?(b|i|pre))&gt;")
			s = unescapeTags.ReplaceAllString(s, "<$1>")
			s = regexp.MustCompile("\r?\n").ReplaceAllString(s, "<br>")
			return template.HTML(s)
		},
		"showGender": func(gender string) string {
			switch gender {
			case "M":
				return "Male"
			case "F":
				return "Female"
			default:
				log.Printf("ERROR: attempted to show unknown gender %q\n", gender)
				return "Unknown"
			}
		},
	}).ParseGlob("./templates/*.tmpl.html"))
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

		pageNum, err := strconv.ParseInt(r.URL.Path[1:], 10, 64)
		if r.URL.Path[1:] == "" {
			pageNum = 1
		} else if err != nil {
			errorPage(w, http.StatusBadRequest)
			return
		}

		userID, _ := getUserID(r)
		profile := getProfile(userID)
		if profile == nil {
			errorPage(w, http.StatusBadRequest)
			return
		}

		db, err := sql.Open("sqlite3", DatabaseURL)
		if err != nil {
			return
		}
		defer db.Close()

		rows, err := db.Query("SELECT messages.id, message, date_created, date_edited, user_account.id, date_joined, first_name, username "+
			"FROM user_account, user_profile, messages WHERE user_account.id=user_profile.account_id and user_account.id=messages.account_id "+
			"ORDER BY date_edited DESC "+
			"LIMIT ? OFFSET ?", messagesPerPage, (pageNum-1)*int64(messagesPerPage))
		if err != nil {
			return
		}

		var messageCount int
		err = db.QueryRow("SELECT COUNT(*) FROM user_account, user_profile, messages " +
			"WHERE user_account.id=user_profile.account_id and user_account.id=messages.account_id").Scan(&messageCount)
		if err != nil {
			return
		}

		var messages []Message
		for rows.Next() {
			var message Message
			err = rows.Scan(&message.MessageID, &message.Message, &message.DateCreated, &message.DateEdited, &message.UserID, &message.DateJoined, &message.FirstName, &message.Username)
			if message.DateEdited != message.DateCreated {
				message.Edited = true
			}
			messages = append(messages, message)
		}

		data := struct {
			Profile     *UserProfile
			Messages    []Message
			CurrentUser int
			IsAdmin     bool
			Viewing     bool
			PageCount   int
			CurrentPage int
		}{
			profile,
			messages,
			userID,
			isAdmin(r),
			false,
			int(math.Ceil(float64(messageCount) / float64(messagesPerPage))),
			int(pageNum),
		}

		renderPage(w, "home", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func viewPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		id, err := strconv.ParseInt(r.URL.Path[6:], 10, 64)
		if err != nil {
			errorPage(w, http.StatusBadRequest)
		}
		userID := int(id)

		profile := getProfile(userID)
		if profile == nil {
			errorPage(w, http.StatusBadRequest)
			return
		}
		data := struct {
			Profile *UserProfile
			IsAdmin bool
			Viewing bool
		}{
			profile,
			isAdmin(r),
			true,
		}
		renderPage(w, "home", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func messagePost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
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

		message := r.FormValue("message")

		if message == "" {
			http.Error(w, errors.New("Empty Message.").Error(), http.StatusBadRequest)
			return
		}

		db, err := sql.Open("sqlite3", DatabaseURL)
		if err != nil {
			return
		}
		defer db.Close()

		tx, err := db.Begin()
		if err != nil {
			return
		}

		_, err = tx.Exec("INSERT INTO messages (account_id, message, date_created, date_edited) VALUES (?, ?, ?, ?)",
			userID, message, time.Now(), time.Now())
		if err != nil {
			tx.Rollback()
			return
		}

		tx.Commit()

		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func editMessageHandler(w http.ResponseWriter, r *http.Request) {
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

		message_id := r.URL.Path[14:]

		err := isMessageCreator(userID, message_id)
		if err != nil && !isAdmin(r) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		message, err := getMessage(message_id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data := struct {
			Message   string
			MessageID string
		}{
			message,
			message_id,
		}
		renderPage(w, "edit_message", data)
	case "POST":
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

		message_id := r.FormValue("message_id")
		message := r.FormValue("message")

		if message == "" {
			http.Error(w, errors.New("Empty Message.").Error(), http.StatusBadRequest)
			return
		}

		err := isMessageCreator(userID, message_id)
		if err != nil && !isAdmin(r) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		db, err := sql.Open("sqlite3", DatabaseURL)
		if err != nil {
			return
		}
		defer db.Close()

		tx, err := db.Begin()
		if err != nil {
			return
		}

		_, err = tx.Exec("UPDATE messages SET message = ?, date_edited = ? where id = ?",
			message, time.Now(), message_id)
		if err != nil {
			tx.Rollback()
			return
		}

		tx.Commit()

		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
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

		message_id := r.FormValue("messageID")

		err := isMessageCreator(userID, message_id)
		if err != nil && !isAdmin(r) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = deleteMessage(message_id)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func editPage(w http.ResponseWriter, r *http.Request) {
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

		session, _ := cookies.Get(r, "session")
		username, _ := session.Values["username"].(string)

		data := struct {
			Profile  *UserProfile
			IsAdmin  bool
			Username string
		}{
			profile,
			isAdmin(r),
			username,
		}

		renderPage(w, "edit", data)
	case "POST":
		password := r.FormValue("password")

		if !isLoggedIn(r) {
			loginPage(w, r)
			return
		}

		accessLevel := r.FormValue("access_level")
		if accessLevel != "" && !isAdmin(r) {
			fmt.Fprintf(w, `
				<body style="background: black; text-align: center;">
					<video src="/images/gandalf.mp4" autoplay loop>You Shall Not Pass!</video>
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

		session, _ := cookies.Get(r, "session")
		userID, _ := session.Values["user_id"].(int)
		err = edit(userID, password, admin, profile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
		session.Values["username"] = username
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
		delete(session.Values, "username")
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
					<video src="/images/gandalf.mp4" autoplay loop>You Shall Not Pass!</video>
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
			session.Values["username"] = username
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

type Message struct {
	FirstName   string
	Username    string
	UserID      int
	DateJoined  time.Time
	DateCreated time.Time
	Message     string
	MessageID   int
	DateEdited  time.Time
	Edited      bool
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

func validateProfile(profile UserProfile) error {
	if !regexp.MustCompile("^[0-9A-Za-zñ ]{1,50}$").MatchString(profile.FirstName) {
		return errors.New("Invalid first name.")
	}

	if !regexp.MustCompile("^[0-9A-Za-zñ ]{1,50}$").MatchString(profile.LastName) {
		return errors.New("Invalid last name.")
	}

	switch profile.Gender {
	case "M":
		if !maleSalutations[profile.Salutation] {
			return errors.New("Invalid salutation.")
		}
	case "F":
		if !femaleSalutations[profile.Salutation] {
			return errors.New("Invalid salutation.")
		}
	default:
		return errors.New("Invalid gender.")
	}

	if age(profile.Birthday) <= 18 {
		return errors.New("Too young.")
	}

	if profile.About == "" {
		return errors.New("Missing about.")
	}

	return nil
}

func register(username, password string, admin bool, profile UserProfile) (int, error) {
	err := validateProfile(profile)
	if err != nil {
		return 0, err
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

	result, err := tx.Exec("INSERT INTO user_account (username, hashed_password, admin, date_joined) VALUES (?, ?, ?, ?)",
		username, hashedPassword, admin, time.Now())
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

func edit(userID int, password string, admin bool, profile UserProfile) error {
	err := validateProfile(profile)
	if err != nil {
		return err
	}

	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("UPDATE user_profile SET first_name = ?, last_name = ?, "+
		"gender = ?, salutation = ?, birthday = ?, about = ? WHERE account_id = ?",
		profile.FirstName, profile.LastName, profile.Gender,
		profile.Salutation, profile.Birthday, profile.About, userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 0)

	_, err = tx.Exec("UPDATE user_account SET hashed_password = ?, admin = ? WHERE id = ?",
		hashedPassword, admin, userID)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()

	return nil
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

func getMessage(message_id string) (message string, err error) {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return "", err
	}
	defer db.Close()
	err = db.QueryRow("SELECT message FROM messages WHERE id=?", message_id).Scan(&message)
	if err != nil {
		return "", errors.New("No such message.")
	}
	return
}

func deleteMessage(message_id string) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec("DELETE FROM messages WHERE id=?", message_id)
	if err != nil {
		return err
	}
	return nil
}

func isMessageCreator(userID int, message_id string) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM messages WHERE account_id=? and id=?", userID, message_id).Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New("Not Message Creator.")
	}

	return nil
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
			admin BOOLEAN NOT NULL DEFAULT FALSE,
      date_joined DATE NOT NULL 
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

	_, err = db.Exec(`
		CREATE TABLE messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id INTEGER,
			
			message VARCHAR(200) NOT NULL,
      date_created DATE NOT NULL,
      date_edited DATE,
			
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
	http.HandleFunc("/edit", editPage)
	http.HandleFunc("/post", messagePost)
	http.HandleFunc("/edit-message/", editMessageHandler)
	http.HandleFunc("/view/", viewPage)
	http.HandleFunc("/delete", deleteMessageHandler)

	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("./images"))))
	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("./styles"))))
	http.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("./scripts"))))

	http.ListenAndServe(":8080", context.ClearHandler(http.DefaultServeMux))
	// http.ListenAndServeTLS(":10443", "certificate/cert.pem", "certificate/key.pem", context.ClearHandler(http.DefaultServeMux))
}
