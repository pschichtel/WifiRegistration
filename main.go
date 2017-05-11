package main

import _ "github.com/mattn/go-sqlite3"
import _ "github.com/go-sql-driver/mysql"
import (
	"os"
	"os/signal"
	"syscall"
	"github.com/amoghe/go-crypt"
	"flag"
	"net/http"
	"fmt"
	"io/ioutil"
	"database/sql"
	"math/rand"
	"time"
	"strings"
)

const AuthCookieName = "auth"

func handleIndex(pass string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if checkPasswordAgainstCookie(r, pass) {
			http.Redirect(w, r, "/list", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}
}
var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func GenerateString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func handleRegisterPage(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method == "POST" {
		r.ParseForm()
		username := strings.TrimSpace(r.PostForm.Get("username"))
		password := r.PostForm.Get("password")

		if len(username) == 0 || len(password) == 0 {
			http.Error(w, "Both username and password require a value!", http.StatusBadRequest)
		} else {
			var random []byte
			rand.Read(random)
			hashed, err := crypt.Crypt(password, "$6$" + GenerateString(16) + "$")
			if err != nil {
				http.Error(w, "Crypt: " + err.Error(), http.StatusInternalServerError)
				return
			}
			var attr = "Password-With-Header"
			var op = ":="
			var passwordHeader = "{Crypt}"
			var value = passwordHeader + hashed
			_, err = db.Exec("INSERT INTO radcheck (username, attribute, op, value) VALUES (?, ?, ?, ?)", username, attr, op, value)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/list", http.StatusFound)

		}

	} else {
		content, err := ioutil.ReadFile("register.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			fmt.Fprintf(w, "%s", content)
		}
	}
}

func handleListPage(w http.ResponseWriter, _ *http.Request, db *sql.DB) {
	var result, err = db.Query("SELECT DISTINCT username FROM radcheck")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		fmt.Fprint(w, "<h1>Available accounts</h1>\n")
		fmt.Fprint(w, "<p><a href=\"/register\">Register new</a></p>")
		fmt.Fprint(w, "<ul>\n")
		for result.Next() {
			var username string
			result.Scan(&username)
			fmt.Fprintf(w, "<li>%s <a href=\"/delete?user=%s\">delete</a></li>", username, username)
		}
		fmt.Fprint(w, "</ul>\n")
	}
}

func handleDeletePage(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var user = r.URL.Query().Get("user")
	if len(user) == 0 {
		http.Error(w, "No user given!", http.StatusBadRequest)
	} else {
		var result, err = db.Exec("DELETE FROM radcheck WHERE username = ?", user)
		var affectedRows, _ = result.RowsAffected()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else if affectedRows == 0 {
			http.Error(w, fmt.Sprintf("User %s not found!", user), http.StatusNotFound)
		} else {
			http.Redirect(w, r, "/list", http.StatusFound)
		}
	}
}

func handleLoginPage(pass string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			r.ParseForm()
			password := r.PostForm.Get("password")

			if password == pass {
				var cookie = http.Cookie{Name:AuthCookieName, Value:password}
				http.SetCookie(w, &cookie)
				http.Redirect(w, r, "/", http.StatusFound)
			} else {
				http.Error(w, "Invalid password!", http.StatusBadRequest)
			}

		} else {
			content, err := ioutil.ReadFile("login.html")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				fmt.Fprintf(w, "%s", content)
			}
		}
	}
}

func withDB(fn func(w http.ResponseWriter, r *http.Request, db *sql.DB), db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r, db)
	}
}

func withLog(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Access: %s %s\n", r.Method, r.URL.Path)
		fn(w, r)
	}
}

func authenticationWrapper(pass string) func(http.HandlerFunc) http.HandlerFunc {
	return func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if checkPasswordAgainstCookie(r, pass) {
				fn(w, r)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
		}
	}
}

func checkPasswordAgainstCookie(r *http.Request, pass string) bool {
	var cookie, err = r.Cookie(AuthCookieName)
	if err != nil {
		return false
	} else {
		return cookie.Value == pass
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	var dsn string
	var driver string
	var listenPort int
	var listenAddr string
	var password string
	flag.StringVar(&driver, "driver", "sqlite3", "Provides the database driver")
	flag.StringVar(&dsn, "dsn", "accounts.db", "Provides the database dsn")
	flag.IntVar(&listenPort, "listen-port", 80, "Provides the listening port")
	flag.StringVar(&listenAddr, "listen-address", "0.0.0.0", "Provides the listening address")
	flag.StringVar(&password, "password", "sicher", "Provides the application password")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	db, sqlErr := sql.Open(driver, dsn)
	if sqlErr != nil {
		fmt.Println("Failed to connect to the database!")
		fmt.Println(sqlErr.Error())
		os.Exit(1)
	} else {
		fmt.Printf("Successfully connected to the database: %s\n", dsn)
	}

	go func() {
		s := <-signals
		fmt.Printf("Received signal %s, terminating...\n", s.String())
		db.Close()
		os.Exit(0)
	}()

	var listenOn = fmt.Sprintf("%s:%d", listenAddr, listenPort)
	fmt.Printf("Listening on %s\n", listenOn)

	var withAuth = authenticationWrapper(password)

	http.HandleFunc("/",		withLog(handleIndex(password)))
	http.HandleFunc("/login",	withLog(handleLoginPage(password)))
	http.HandleFunc("/register",	withLog(withAuth(withDB(handleRegisterPage, db))))
	http.HandleFunc("/list",		withLog(withAuth(withDB(handleListPage, db))))
	http.HandleFunc("/delete",	withLog(withAuth(withDB(handleDeletePage, db))))

	var listenErr = http.ListenAndServe(listenOn, nil)
	if listenErr != nil {
		fmt.Println(sqlErr.Error())
		os.Exit(1)
	}
}