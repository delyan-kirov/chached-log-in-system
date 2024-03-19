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

func Test() {
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
			name VARCHAR(100),
			age INT
		)
	`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		panic(err)
	}
	fmt.Println("Table 'users' created successfully!")

	// populate test table

	insertQuery := `
		INSERT INTO users (name, age) VALUES ($1, $2)
	`
	_, err = db.Exec(insertQuery, "John Doe", 30)
	if err != nil {
		panic(err)
	}
	fmt.Println("User 'John Doe' added successfully!")
}
