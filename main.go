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
)

func redirectToRegister(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/register", http.StatusFound)
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
		username := r.PostForm.Get("username")
		password := r.PostForm.Get("password")

		if len(username) == 0 || len(password) == 0 {
			http.Error(w, "Both username and password require a value!", http.StatusBadRequest)
		} else {
			var random []byte
			rand.Read(random)
			hashed, err := crypt.Crypt(password, "$6$" + GenerateString(16) + "$")
			if (err != nil) {
				http.Error(w, "Crypt: " + err.Error(), http.StatusInternalServerError)
				return;
			}
			_, err = db.Exec("INSERT INTO accounts (username, password) VALUES (?, ?)", username, hashed)
			if (err != nil) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return;
			}
			fmt.Fprintf(w, "Successfully registered %s!", username + ":" + hashed)

		}

	} else {
		content, err := ioutil.ReadFile("register.html");
		if (err != nil) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			fmt.Fprintf(w, "%s", content)
		}
	}
}

func makeHandler(fn func(w http.ResponseWriter, r *http.Request, db *sql.DB), db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r, db)
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	var dbPath string
	var driver string
	flag.StringVar(&driver, "driver", "sqlite3", "Provides the database driver")
	flag.StringVar(&dbPath, "dsn", "accounts.db", "Provides the database dsn")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	db, err := sql.Open(driver, dbPath)
	if (err != nil) {
		fmt.Println("Failed to connect to the database!")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	go func() {
		s := <-signals
		fmt.Printf("Received signal %s, terminating...\n", s.String())
		db.Close()
		os.Exit(0)
	}()

	http.HandleFunc("/", redirectToRegister)
	http.HandleFunc("/register", makeHandler(handleRegisterPage, db))
	http.ListenAndServe(":9001", nil)
}