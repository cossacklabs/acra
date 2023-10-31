// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"context"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	_ "github.com/lib/pq"
)

func main() {
	//mysql := flag.Bool("mysql", false, "Use MySQL driver")
	//_ = flag.Bool("postgresql", false, "Use PostgreSQL driver (default if nothing else set)")
	//dbname := flag.String("db_name", "acra", "Database name")
	//host := flag.String("host", "127.0.0.1", "Database host")
	//port := flag.Int("port", 9494, "Database port")
	//user := flag.String("db_user", "test", "Database user")
	//password := flag.String("db_password", "password", "Database user's password")
	//data := flag.String("data", "", "Data to save")
	//printData := flag.Bool("print", false, "Print data from database")
	//publicKey := flag.String("public_key", "", "Path to public key")
	//flag.Parse()

	//connectionString := fmt.Sprintf("user=test password=test dbname=test host=localhost port=9393 sslmode=disable")
	//driver := "postgres"
	//if *mysql {
	//	// username:password@protocol(address)/dbname?param=value
	//	// https://github.com/go-sql-driver/mysql#dsn-data-source-name
	//	connectionString = fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", *user, *password, *host, *port, *dbname)
	//	driver = "mysql"
	//}

	//acraPublic, err := utils.LoadPublicKey(*publicKey)
	//if err != nil {
	//	panic(err)
	//}

	connConfig, err := pgx.ParseConfig("postgres://test:test@localhost:9393/test")
	if err != nil {
		panic(err)
	}

	connConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(context.Background(), connConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	if err := conn.Ping(context.Background()); err != nil {
		panic(err)
	}

	defer conn.Close(context.Background())

	var name string
	var weight int64
	_, err = conn.Exec(context.Background(), "insert into users (id, phone_number, ssn, email, firstname, lastname) values ($1, $2, $3, $4,$5, $6)", 1, []byte{0, 0, 0, 0}, []byte("12322324"), []byte("zhmaka99@gmail.com"), []byte("Artem"), "Zhmaka")
	if err != nil {
		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(name, weight)
	//
	//err = db.Ping()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//_, err = db.Exec("insert into users (id, phone_number, ssn, email, firstname, lastname) values (1, '+380996037987', '123456789', 'zhmaka99@gmail.com','Artem', 'Zhmaka'), (2, '+380996037987', '123456789', 'zhmaka99@gmail.com','Artem', 'Zhmaka');")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//query := `SELECT * FROM users;`
	//fmt.Printf("Select from db with command: '%v'\n", query)
	//rows, err := db.Query(query)
	//defer rows.Close()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//var data1 interface{}
	//var data2 string
	//var data3 string
	//var data4 string
	//var data5 string
	//var data6 string
	//
	//fmt.Println("data - raw_data")
	//for rows.Next() {
	//	err := rows.Scan(&data1, &data2, &data3, &data4, &data5, &data6)
	//	if err != nil {
	//		panic(err)
	//	}
	//	fmt.Printf("data: %v\nraw_data: %v\n\n", data1, data)
	//}

	fmt.Println("Finish")
}
