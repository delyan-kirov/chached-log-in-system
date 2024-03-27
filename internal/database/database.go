package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const (
	db_host     = "localhost"
	db_port     = 5432
	db_user     = "postgres"
	db_password = "mysecretpassword"
	db_name     = "postgres"
)

type User struct {
	Name     string
	Password []byte
}

func (A User) Equals(B User) bool {
	return A.Name == B.Name
}

type UserSettings struct {
	id []byte
}

func AddUser(user User) error {
	// Connect to db
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		db_host, db_port, db_user, db_password, db_name)

	db, err := sql.Open("postgres", psqlInfo)
	defer db.Close()

	if err != nil {
		return fmt.Errorf("[ERROR] Could not connect to database: %s\n", err)
	}

	fmt.Println("Successfully connected to the PostgreSQL database!")

	// Insert user
	insertQuery := `
		INSERT INTO users (name, password) VALUES ($1, $2)
	`
	_, err = db.Exec(insertQuery, user.Name, user.Password)
	if err != nil {
		return fmt.Errorf("Could not write to database: %s\n", err)
	}
	fmt.Printf("Successfully created user: %s\n", user.Name)
	return nil
}

func AuthUser(userName string) (User, error) {
	// Connect to db
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		db_host, db_port, db_user, db_password, db_name)

	db, err := sql.Open("postgres", psqlInfo)
	defer db.Close()

	if err != nil {
		fmt.Println("[ERROR] Cannot connect to database")
		return User{}, nil
	}

	fmt.Println("Successfully connected to the PostgreSQL database!")

	const findUserQuery = "SELECT name, password FROM users WHERE name = $1"
	row := db.QueryRow(findUserQuery, userName) // no matches is error
	var user User
	err = row.Scan(&user.Name, &user.Password)
	if err != nil {
		fmt.Println("[ERROR] Could not find user in database")
		return User{}, err
	}

	return user, nil
}

func AddUserSettings() {
	panic("[TODO]")
}

func getUserSettings() {
	panic("[TODO]")
}

func Connect() {
	// Connect to db
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		db_host, db_port, db_user, db_password, db_name)

	db, err := sql.Open("postgres", psqlInfo)
	defer db.Close()

	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully connected to the PostgreSQL database!")

	// Create test table
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			name VARCHAR(100) UNIQUE NOT NULL,
			password BYTEA NOT NULL
		)
	`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		panic(err)
	}
	fmt.Println("Table 'users' created successfully!")
}

// TODO: Make sure to return the errors
