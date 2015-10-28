package main

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DatabaseURL = "file:database.sqlite?cache=shared&mode=rwc"

var cookies = sessions.NewCookieStore([]byte("813629774771309960518707211349999998"))

var templates *template.Template

const messagesPerPage = 10
const backUpDirectory = "backups\\"

const (
	Paid       = 0
	None       = 1
	CheckedOut = 2
)

func initTemplates() {
	templates = template.Must(template.New("").Funcs(template.FuncMap{
		"showDate":     func(date time.Time) string { return date.Format("Jan 2, 2006") },
		"showDateTime": func(date time.Time) string { return date.Format(time.RFC850) },
		"showISODate":  func(date time.Time) string { return date.Format("2006-01-02") },
		"minus":        func(a, b int) int { return a - b },
		"add":          func(a, b int) int { return a + b },
		"boldItalics": func(s string) template.HTML {
			s = template.HTMLEscapeString(s)
			imageTags := regexp.MustCompile(`&lt;img\s+src=&#34;(.*?)&#34;&gt;`)
			s = imageTags.ReplaceAllString(s, `<img src="$1" style="max-width:570px;">`)
			unescapeTags := regexp.MustCompile("&lt;(/?(b|i|pre|u|sub|sup|strike|marquee))&gt;")
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
		"unescape": func(s string) template.URL {
			return template.URL(s)
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

		pageNum, err := strconv.Atoi(r.URL.Path[1:])
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

		rows := getMessages(messagesPerPage, (pageNum-1)*messagesPerPage)
		if rows == nil {
			return
		}

		messages := rowToMessageArray(rows)

		var messageCount int
		err = db.QueryRow("SELECT COUNT(*) FROM user_account, user_profile, messages " +
			"WHERE user_account.id=user_profile.account_id and user_account.id=messages.account_id").Scan(&messageCount)
		if err != nil {
			return
		}

		data := struct {
			Profile     *UserProfile
			Messages    []Message
			UserID      int
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
		userID, err := strconv.Atoi(r.URL.Path[6:])
		if err != nil {
			errorPage(w, http.StatusBadRequest)
		}

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
		if v, _ := strconv.Atoi(r.FormValue("user_id")); v != userID {
			http.Error(w, "Currently logged in as a different user. Refresh please.", http.StatusBadRequest)
			return
		}
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
			UserID    int
		}{
			message,
			message_id,
			userID,
		}
		renderPage(w, "edit_message", data)
	case "POST":
		if !isLoggedIn(r) {
			loginPage(w, r)
			return
		}

		userID, _ := getUserID(r)

		if v, _ := strconv.Atoi(r.FormValue("user_id")); v != userID {
			http.Error(w, "Currently logged in as a different user. Refresh please.", http.StatusBadRequest)
			return
		}

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
		if v, _ := strconv.Atoi(r.FormValue("user_id")); v != userID {
			http.Error(w, "Currently logged in as a different user. Refresh please.", http.StatusBadRequest)
			return
		}

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
			UserID   int
		}{
			profile,
			isAdmin(r),
			username,
			userID,
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

		if v, _ := strconv.Atoi(r.FormValue("user_id")); v != userID {
			http.Error(w, "Currently logged in as a different user. Refresh please.", http.StatusBadRequest)
			return
		}

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

func downloadFilesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isAdmin(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.ServeFile(w, r, backUpDirectory+r.URL.Path[10:])
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
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
		query := r.FormValue("q")
		pageNum, err := strconv.Atoi(r.FormValue("p"))
		if err != nil {
			pageNum = 1
		}

		messageCount, messages := search(query, messagesPerPage, (pageNum-1)*messagesPerPage)
		data := struct {
			Profile     *UserProfile
			Messages    []Message
			UserID      int
			IsAdmin     bool
			PageCount   int
			CurrentPage int
			Query       string
		}{
			profile,
			messages,
			userID,
			isAdmin(r),
			int(math.Ceil(float64(messageCount) / float64(messagesPerPage))),
			int(pageNum),
			query,
		}
		renderPage(w, "search", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func advancedSearchHandler(w http.ResponseWriter, r *http.Request) {
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

		pageNum, err := strconv.Atoi(r.FormValue("p"))
		if err != nil {
			pageNum = 1
		}
		inputs := 1
		options := []string{"date_created", "date_edited", "first_name", "username", "last_name"}
		comparison := []string{"<=", ">=", "="}
		var values []string
		var andor []string
		var check []string
		var operator []string
		for r.FormValue("value"+strconv.Itoa(inputs)) != "" {
			checkForm := "check" + strconv.Itoa(inputs)
			if !contains(r.FormValue(checkForm), options) {
				errorPage(w, http.StatusBadRequest)
				return
			}
			check = append(check, r.FormValue(checkForm))

			operatorForm := "operator" + strconv.Itoa(inputs)
			if !contains(r.FormValue(operatorForm), comparison) {
				errorPage(w, http.StatusBadRequest)
				return
			}
			operator = append(operator, r.FormValue(operatorForm))

			if inputs != 1 {
				andorForm := "andor" + strconv.Itoa(inputs)
				andorVal := r.FormValue(andorForm)
				if !(andorVal == "OR" || andorVal == "AND") {
					errorPage(w, http.StatusBadRequest)
					return
				}
				andor = append(andor, andorVal)
			}

			values = append(values, r.FormValue("value"+strconv.Itoa(inputs)))
			inputs++
		}
		messageCount, messages := advancedSearch(values, andor, check, operator, messagesPerPage, (pageNum-1)*messagesPerPage)
		data := struct {
			Profile     *UserProfile
			Messages    []Message
			UserID      int
			IsAdmin     bool
			PageCount   int
			CurrentPage int
			Query       string
		}{
			profile,
			messages,
			userID,
			isAdmin(r),
			int(math.Ceil(float64(messageCount) / float64(messagesPerPage))),
			int(pageNum),
			regexp.MustCompile("p=\\d+").ReplaceAllString(r.URL.RawQuery, ""),
		}
		renderPage(w, "advanced-search", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func backUpMessagesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isAdmin(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		files, _ := ioutil.ReadDir(backUpDirectory)
		data := struct {
			Files []os.FileInfo
		}{
			files,
		}
		renderPage(w, "backup", data)
	case "POST":
		if !isAdmin(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		backUpMessages()
		http.Redirect(w, r, "/backup", http.StatusFound)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func storePageHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		data := struct {
			IsAdmin bool
			Items   []Item
		}{
			isAdmin(r),
			getStoreItems(),
		}
		renderPage(w, "store", data)
	case "POST":
		if !isAdmin(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		backUpMessages()
		http.Redirect(w, r, "/backup", http.StatusFound)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func viewItemHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		itemID, err := strconv.Atoi(r.URL.Path[len("/view-item/"):])
		if err != nil {
			http.Error(w, "No such item", http.StatusBadRequest)
			return
		}
		item, err := getStoreItem(itemID)
		if err != nil {
			http.Error(w, "No such item", http.StatusBadRequest)
			return
		}
		renderPage(w, "view-item", item)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func addItemHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isAdmin(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		renderPage(w, "add-item", nil)
	case "POST":
		if !isAdmin(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		name := r.FormValue("name")
		description := r.FormValue("description")
		image := r.FormValue("image")
		price, err := strconv.ParseFloat(r.FormValue("price"), 64)
		if err != nil {
			http.Error(w, "Price should be a decimal", http.StatusBadRequest)
			return
		}
		err = addItem(name, description, image, price)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/store", http.StatusFound)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func addToCartHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		userID, _ := getUserID(r)
		itemID, err := strconv.Atoi(r.FormValue("item_id"))
		if err != nil {
			http.Error(w, "Not an Item", http.StatusBadRequest)
			return
		}

		db, err := sql.Open("sqlite3", DatabaseURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer db.Close()

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM items WHERE id = ?", itemID).Scan(&count)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if count == 0 {
			http.Error(w, "Not an Item", http.StatusBadRequest)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var cartID int
		err = tx.QueryRow("SELECT id FROM carts WHERE account_id = ? AND status = ? ORDER BY id DESC ", userID, None).Scan(&cartID)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Current Cart is checked out", http.StatusBadRequest)
			return
		}

		_, err = tx.Exec("INSERT INTO itemsInACart (cart_id, item_id, count) VALUES (?, ?, ?)", cartID, itemID, 1)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Duplicate item in cart.", http.StatusBadRequest)
			return
		}

		tx.Commit()

		http.Redirect(w, r, "/store", http.StatusFound)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func viewCartHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		userID, _ := getUserID(r)
		cart, total, cartID, status, url := getCart(userID)
		var token string
		if status == 2 {
			token = url[len("https://www.sandbox.paypal.com/cgi-bin/webscr?cmd=_express-checkout&token="):]
		}
		data := struct {
			Total  float64
			Items  []CartItem
			CartID int
			UserID int
			Pay    bool
			URL    string
			Status int
			Token  string
		}{
			total,
			cart,
			cartID,
			userID,
			true && status == None,
			url,
			status,
			token,
		}
		renderPage(w, "view-cart", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func viewSpecificCartHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		cartID, err := strconv.Atoi(r.URL.Path[len("/view-cart/"):])
		if err != nil {
			http.Error(w, "Wrong cart id", http.StatusBadRequest)
			return
		}
		userID, _ := getUserID(r)
		cart, total, userID2 := getCartWithCartID(cartID)
		if userID != userID2 {
			http.Error(w, "Unauthorized access.", http.StatusBadRequest)
			return
		}
		data := struct {
			Total  float64
			Items  []CartItem
			Pay    bool
			CartID int
		}{
			total,
			cart,
			false,
			cartID,
		}
		renderPage(w, "view-cart", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func viewTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		userID, _ := getUserID(r)

		data := struct {
			Transactions []Cart
		}{
			getTransactions(userID),
		}
		renderPage(w, "view-transactions", data)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func updateItemCountHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		cartID, err := strconv.Atoi(r.FormValue("cart_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		itemID, err := strconv.Atoi(r.FormValue("item_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		userID, _ := getUserID(r)
		count, err := strconv.Atoi(r.FormValue("count"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if count == 0 {
			deleteItemFromCart(cartID, itemID, userID)
		} else {
			updateItemCount(cartID, itemID, count, userID)
		}
		http.Redirect(w, r, "/view-cart", http.StatusFound)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func getAccessToken() (string, error) {
	duration, _ := time.ParseDuration("0s")
	client := &http.Client{
		Timeout: duration,
	}
	req, err := http.NewRequest("POST", "https://api.sandbox.paypal.com/v1/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept-Language", "en_US")
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("ARSY2kxA9yYYb2wwe5bOHgWtrLfrN86ft6X4tRjWfPA-KaBIKud-Haj2FuirRzWfHaWUmGyCQp_XE_XN", "EKhrhqlNnRM4DmOfldIC57RfDH8djuaPi-Qv1RYD98mlXR7qt-MrzL6Xs1nn7ciTzJgR9PhByo9fOlWF")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Paypal dead")
	}
	var resBody map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&resBody)
	accessToken := resBody["access_token"].(string)
	return accessToken, nil
}

func payHandler(w http.ResponseWriter, r *http.Request) {
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	switch r.Method {
	case "POST":
		duration, _ := time.ParseDuration("0s")
		client := &http.Client{
			Timeout: duration,
		}

		userID, _ := getUserID(r)
		cart, total, cartID, _, _ := getCart(userID)

		if len(cart) == 0 {
			http.Error(w, "No items in cart", http.StatusBadRequest)
		}

		accessToken, err := getAccessToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		items := ""
		for i, v := range cart {
			if i != len(cart)-1 {
				items = items + `{"quantity":"` + fmt.Sprintf("%v", v.Count) + `", "name":"` + v.Name + `", "price":"` + fmt.Sprintf("%v", v.Price) + `", "currency":"USD"},`
			} else {
				items = items + `{"quantity":"` + fmt.Sprintf("%v", v.Count) + `", "name":"` + v.Name + `", "price":"` + fmt.Sprintf("%v", v.Price) + `", "currency":"USD"}`
			}
		}
		items = `"item_list": { "items":[` + items + `] }`
		req, err := http.NewRequest("POST", "https://api.sandbox.paypal.com/v1/payments/payment",
			strings.NewReader(`{
      "intent":"sale",
      "redirect_urls":{
        "return_url":"http://`+r.Host+`/success",
        "cancel_url":"http://`+r.Host+`/cancel"
      },
      "payer":{
        "payment_method":"paypal"
      },
      "transactions":[
        {
          "amount":{
            "total":"`+fmt.Sprintf("%v", total)+`",
            "currency":"USD"
          },
          "description":"This is the payment transaction description.",`+items+
				`
        }
      ]
    }`))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+accessToken+"")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Paypal dead", http.StatusBadRequest)
			return
		}
		var resBody map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&resBody)
		id := resBody["id"].(string)
		url := resBody["links"].([]interface{})[1].(map[string]interface{})["href"].(string)
		updateCartWithPaymentID(cartID, id, url)
		http.Redirect(w, r, url, http.StatusFound)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func successHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		accessToken, err := getAccessToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		duration, _ := time.ParseDuration("0s")
		client := &http.Client{
			Timeout: duration,
		}
		paymentID := r.FormValue("paymentId")
		payerID := r.FormValue("PayerID")
		req, err := http.NewRequest("POST", "https://api.sandbox.paypal.com/v1/payments/payment/"+paymentID+"/execute/", strings.NewReader(`{"payer_id":"`+payerID+`"}`))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+accessToken+"")
		_, err = client.Do(req)
		if err != nil {
			http.Error(w, "Paypal dead", http.StatusBadRequest)
			return
		}
		updateCartStatusPaid(paymentID)
		http.Redirect(w, r, "/view-transactions", http.StatusFound)
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func cancelHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		token := r.FormValue("token")
		updateCartStatus(token, None)
		http.Redirect(w, r, "/view-cart", http.StatusFound)
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

type Item struct {
	Name        string
	Description string
	Image       string
	Price       float64
	ID          int
}

type CartItem struct {
	ID    int
	Name  string
	Price float64
	Count int
	Total float64
}

type Cart struct {
	ID    int
	Total float64
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

func search(query string, limit int, offset int) (int, []Message) {
	query = "%" + query + "%"
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return 0, nil
	}
	defer db.Close()
	var count int
	err = db.QueryRow("SELECT count(*) "+
		"FROM user_account, user_profile, messages WHERE user_account.id=user_profile.account_id AND user_account.id=messages.account_id "+
		"AND (message LIKE ? OR username LIKE ? OR first_name LIKE ? OR last_name LIKE ?) ", query, query, query, query).Scan(&count)
	if offset > count {
		offset = count / 10 * 10
	}
	rows, err := db.Query("SELECT messages.id, message, date_created, date_edited, user_account.id, date_joined, first_name, username "+
		"FROM user_account, user_profile, messages WHERE user_account.id=user_profile.account_id and user_account.id=messages.account_id "+
		"AND (message LIKE ? OR username LIKE ? OR first_name LIKE ? OR last_name LIKE ?) "+
		"ORDER BY date_edited DESC "+
		"LIMIT ? OFFSET ?", query, query, query, query, limit, offset)
	return count, rowToMessageArray(rows)
}

func advancedSearch(values, andor, check, operator []string, limit, offset int) (int, []Message) {
	if len(values) <= 0 {
		return 0, nil
	}
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return 0, nil
	}
	defer db.Close()
	selectMessages := "SELECT messages.id, message, date_created, date_edited, user_account.id, date_joined, first_name, username "
	selectCount := "SELECT COUNT(*) "
	statement := "FROM user_account, user_profile, messages WHERE user_account.id=user_profile.account_id and user_account.id=messages.account_id " +
		"AND ("
	args := []interface{}{}
	for i := 0; i < len(values); i++ {
		if i != len(values)-1 {
			statement += check[i] + " " + operator[i] + " ? " + andor[i] + " "
		} else {
			statement += check[i] + " " + operator[i] + " ?) "
		}
		args = append(args, values[i])
	}
	var count int
	db.QueryRow(selectCount+statement, args...).Scan(&count)
	statement += "ORDER BY date_edited DESC "
	statement += "LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := db.Query(selectMessages+statement, args...)

	return count, rowToMessageArray(rows)
}

func rowToMessageArray(rows *sql.Rows) []Message {
	var messages []Message
	for rows.Next() {
		var message Message
		rows.Scan(&message.MessageID, &message.Message, &message.DateCreated, &message.DateEdited, &message.UserID, &message.DateJoined, &message.FirstName, &message.Username)
		if message.DateEdited != message.DateCreated {
			message.Edited = true
		}
		messages = append(messages, message)
	}
	return messages
}

func backUpMessages() {
	if _, err := os.Stat("backups"); os.IsNotExist(err) {
		os.Mkdir("backups", os.ModeDir)
	}
	f, err := os.Create(backUpDirectory + time.Now().Format("2006-01-02-150405") + ".csv")
	defer f.Close()
	w := csv.NewWriter(bufio.NewWriter(f))
	rows := getAllMessages()
	var message [4]string
	w.Write([]string{"Username", "Date Posted", "Date Edited", "Message"})
	for rows.Next() {
		var posted, edited time.Time
		err = rows.Scan(&message[0], &posted, &edited, &message[3])
		message[1] = posted.Format(time.RFC850)
		message[2] = edited.Format(time.RFC850)
		message[3] = regexp.MustCompile("\r?\n").ReplaceAllString(message[3], "<br>")
		if err != nil {
			return
		}
		err = w.Write(message[:])
		if err != nil {
			return
		}
	}

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

	result, err = tx.Exec("INSERT INTO carts (account_id, status) VALUES (?, ?)",
		userID, None)
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

func contains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func getMessages(limit, offset int) *sql.Rows {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT messages.id, message, date_created, date_edited, user_account.id, date_joined, first_name, username "+
		"FROM user_account, user_profile, messages WHERE user_account.id=user_profile.account_id and user_account.id=messages.account_id "+
		"ORDER BY date_edited DESC "+
		"LIMIT ? OFFSET ?", limit, offset)

	if err != nil {
		return nil
	}
	return rows
}

func getAllMessages() *sql.Rows {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT username, date_created, date_edited, message " +
		"FROM user_account, user_profile, messages WHERE user_account.id=user_profile.account_id and user_account.id=messages.account_id " +
		"ORDER BY date_edited DESC")

	if err != nil {
		return nil
	}
	return rows
}

func getStoreItems() (items []Item) {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, name, description, image, price " +
		"FROM items ")

	if err != nil {
		return
	}

	for rows.Next() {
		var item Item
		rows.Scan(&item.ID, &item.Name, &item.Description, &item.Image, &item.Price)
		items = append(items, item)
	}
	return
}

func getStoreItem(itemID int) (item Item, err error) {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return
	}
	defer db.Close()

	err = db.QueryRow("SELECT id, name, count, total, price "+
		"FROM items WHERE id = ?", itemID).Scan(&item.ID, &item.Name, &item.Description, &item.Image, &item.Price)

	if err != nil {
		return
	}

	return
}

func getCartWithCartID(cartID int) (cart []CartItem, total float64, userID int) {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT account_id, item_id, name, price, count "+
		"FROM carts, itemsInACart, items WHERE carts.id = cart_id AND carts.id = ? AND item_id = items.ID", cartID)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for rows.Next() {
		var item CartItem
		rows.Scan(&userID, &item.ID, &item.Name, &item.Price, &item.Count)
		item.Total = item.Price * float64(item.Count)
		total = total + item.Total
		cart = append(cart, item)
	}

	return
}

func getCart(userID int) (cart []CartItem, total float64, cartID int, status int, url string) {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return
	}
	defer db.Close()

	err = db.QueryRow("SELECT id, status, url FROM carts WHERE account_id = ? AND status != ? ORDER BY id DESC ", userID, Paid).Scan(&cartID, &status, &url)
	if err != nil {
		return
	}
	rows, err := db.Query("SELECT item_id, name, price, count "+
		"FROM carts, itemsInACart, items WHERE carts.id = cart_id AND carts.id = ? AND item_id = items.ID", cartID)

	if err != nil {

		fmt.Println(err.Error())
		return
	}

	for rows.Next() {
		var item CartItem
		rows.Scan(&item.ID, &item.Name, &item.Price, &item.Count)
		item.Total = item.Price * float64(item.Count)
		total = total + item.Total
		cart = append(cart, item)
	}

	return
}

func addItem(name, description, image string, price float64) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO items (name, description, image, price) VALUES (?, ?, ?, ?)",
		name, description, image, price)

	if err != nil {
		return err
	}
	return nil
}

func getTransactions(userID int) (carts []Cart) {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, total FROM carts WHERE account_id = ? AND status = ?", userID, Paid)
	if err != nil {
		return
	}

	for rows.Next() {
		var cart Cart
		rows.Scan(&cart.ID, &cart.Total)
		carts = append(carts, cart)
	}
	return carts
}

func updateItemCount(cartID, itemID, count, userID int) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	//check if payed or not for both delete and update

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	var cartCount int

	err = tx.QueryRow("SELECT COUNT(*) FROM itemsInACart, carts WHERE carts.id = cart_id AND cart_id = ? AND item_id = ? AND status = ? AND account_id = ?", cartID, itemID, None, userID).Scan(&cartCount)
	if err != nil {
		tx.Rollback()
		return err
	}

	if cartCount == 0 {
		tx.Rollback()
		return errors.New("Not owner or status payed or checkedout")
	}

	_, err = tx.Exec("UPDATE itemsInACart SET count = ? WHERE cart_id = ? AND item_id = ?", count, cartID, itemID)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func deleteItemFromCart(cartID, itemID, userID int) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	var cartCount int

	err = tx.QueryRow("SELECT COUNT(*) FROM itemsInACart, carts WHERE carts.id = cart_id AND cart_id = ? AND item_id = ? AND status = ? AND account_id = ?", cartID, itemID, None, userID).Scan(&cartCount)
	if err != nil {
		tx.Rollback()
		return err
	}

	if cartCount == 0 {
		tx.Rollback()
		return errors.New("Not owner or status payed or checkedout")
	}

	_, err = tx.Exec("DELETE FROM itemsInACart WHERE cart_id = ? AND item_id = ?", cartID, itemID)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func updateCartWithPaymentID(cartID int, paymentID string, url string) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("UPDATE carts SET payment_id = ?, status = ?, url = ? WHERE id = ?", paymentID, CheckedOut, url, cartID)

	return err
}

func updateCartStatus(token string, status int) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("UPDATE carts SET status = ? WHERE status != ? AND url LIKE ?", Paid, status, "%"+token)

	return err
}

func updateCartStatusPaid(paymentID string) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	var userID int
	db.QueryRow("SELECT account_id FROM carts WHERE payment_id = ?", paymentID).Scan(&userID)
	if err != nil {
		return err
	}

	_, total, _, _, _ := getCart(userID)

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO carts (account_id, status) VALUES (?, ?)", userID, None)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec("UPDATE carts SET status = ?, total = ? WHERE payment_id = ?", Paid, total, paymentID)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
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

	_, err = db.Exec(`
		CREATE TABLE items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
			
			name VARCHAR(200) NOT NULL,
      description VARCHAR(200) NOT NULL,
      image VARCHAR(200),
      price DECIMAL NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE carts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id INTEGER,
      
      total DECIMAL,
			status INTEGER,
			payment_id TEXT,
      url TEXT DEFAULT '',
      
			FOREIGN KEY(account_id) REFERENCES user_account(id)
		)
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		CREATE TABLE itemsInACart (
      cart_id INTEGER,
      item_id INTEGER,
      
      count INTEGER,
			
      PRIMARY KEY(cart_id, item_id),
      FOREIGN KEY(item_id) REFERENCES items(id)
    )
	`)
	if err != nil {
		return err
	}

	_, err = register("admin", "admin", true, UserProfile{"Admin", "Admin", "M", "Mr", time.Date(1990, time.January, 1, 0, 0, 0, 0, time.UTC), "Admin"})
	addItem("Donate $5", "Donate $5", "https://www.paypalobjects.com/webstatic/en_US/btn/btn_donate_92x26.png", 5.00)
	addItem("Donate $10", "Donate $10", "https://www.paypalobjects.com/webstatic/en_US/btn/btn_donate_92x26.png", 10.00)
	addItem("Donate $20", "Donate $20", "https://www.paypalobjects.com/webstatic/en_US/btn/btn_donate_92x26.png", 20.00)

	return err
}

func ipnHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		r.ParseForm()
		for k, v := range r.PostForm {
			fmt.Println("Key: ", k)
			fmt.Println("Value: ", v)
		}
		if r.FormValue("payment_status") != "Completed" {
			return
		}
		params := strings.Split(r.FormValue("custom"), ",")
		switch params[0] {
		case "donate":
			userID, _ := strconv.Atoi(params[1])
			donation, _ := strconv.ParseFloat(r.FormValue("payment_gross"), 64)
			fmt.Println(addDonation(userID, donation))
		case "buy":
			userID, _ := strconv.Atoi(params[1])
			cartID, _ := strconv.Atoi(params[2])
			bought, _ := strconv.ParseFloat(r.FormValue("payment_gross"), 64)
			addBought(userID, cartID, bought)
		}
	default:
		errorPage(w, http.StatusMethodNotAllowed)
	}
}

func addBought(userID, cartID int, bought float64) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	_, total, _ := getCartWithCartID(cartID)

	if bought != total {
		return errors.New("Not the same with total")
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO carts (account_id, payed) VALUES (?, ?)", userID, false)
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.Exec("UPDATE carts SET payed = ?, total = ? WHERE id = ?", true, total, cartID)
	if err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func addDonation(userID int, donation float64) error {
	db, err := sql.Open("sqlite3", DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	result, err := tx.Exec("INSERT INTO carts (account_id, payed, total) VALUES (?, ?, ?)", userID, true, donation)
	if err != nil {
		tx.Rollback()
		return err
	}
	cartID, err := result.LastInsertId()
	if err != nil {
		tx.Rollback()
		return err
	}
	var itemID int
	switch donation {
	case 5:
		itemID = 1
	case 10:
		itemID = 2
	case 20:
		itemID = 3
	default:
		tx.Rollback()
		return errors.New("No such donation value.")
	}
	result, err = tx.Exec("INSERT INTO itemsInACart (cart_id, item_id, count) VALUES (?, ?, ?)", cartID, itemID, 1)
	if err != nil {
		tx.Rollback()
		return err
	}
	tx.Commit()
	return nil
}

func redir(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ipn" {
		ipnHandler(w, r)
	} else {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
	}
}

func main() {
	fmt.Println(createDB())
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
	http.HandleFunc("/backup", backUpMessagesHandler)
	http.HandleFunc("/download/", downloadFilesHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/advanced-search", advancedSearchHandler)
	http.HandleFunc("/store", storePageHandler)
	http.HandleFunc("/add-item", addItemHandler)
	http.HandleFunc("/view-item/", viewItemHandler)
	http.HandleFunc("/ipn", ipnHandler)
	http.HandleFunc("/add-cart", addToCartHandler)
	http.HandleFunc("/view-cart", viewCartHandler)
	http.HandleFunc("/view-cart/", viewSpecificCartHandler)
	http.HandleFunc("/view-transactions", viewTransactionsHandler)
	http.HandleFunc("/update-cart", updateItemCountHandler)
	http.HandleFunc("/pay-now", payHandler)
	http.HandleFunc("/success", successHandler)
	http.HandleFunc("/cancel", cancelHandler)

	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("./images"))))
	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("./styles"))))
	http.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("./scripts"))))

	go http.ListenAndServe(":80", http.HandlerFunc(redir))
	http.ListenAndServeTLS(":443", "certificate/cert.pem", "certificate/key.pem", context.ClearHandler(http.DefaultServeMux))
}
