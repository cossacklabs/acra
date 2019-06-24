package benchmark

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/lib/pq"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestDebug(t *testing.T) {
	db, err := sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=9393")
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	result, err := db.Query(`select * from test_raw where ciphertext='\x6d5f745f6a5f6d407961686f6f2e636f6d'`)
	if err != nil {
		panic(err)
	}

	var id int
	var plaintext []byte
	var ciphertext []byte
	var blindIndex []byte

	for result.Next() {
		err := result.Scan(&id, &plaintext, &ciphertext, &blindIndex)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(id, hex.EncodeToString(plaintext), hex.EncodeToString(ciphertext), hex.EncodeToString(blindIndex))
	}
}

// tests for current ACRA-EE version
func TestRecreateTableSubstring(t *testing.T) {
	db, err := sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=5432")
	if err != nil {
		t.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("DROP TABLE IF EXISTS test_raw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("DROP SEQUENCE IF EXISTS test_raw_seq")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE SEQUENCE test_raw_seq START 1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE TABLE test_raw(id INTEGER PRIMARY KEY DEFAULT nextval('test_raw_seq'), plaintext BYTEA, ciphertext BYTEA);")
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateNewInput(t *testing.T) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s1)

	material, err := LoadDataMaterial("emails")
	if err != nil {
		t.Fatal(err)
	}

	const rows = 10000
	const dataDistribution = 1

	if dataDistribution < 1 || dataDistribution > rows || dataDistribution > MAX_DATA_DISTRIBUTION {
		t.Fatal("bad dataDistribution")
	}

	var input [rows]string
	var dataChunks [dataDistribution]string
	var dataChunksBytes [dataDistribution][]byte

	for i := 0; i < len(dataChunks); i++ {
		dataChunksBytes[i] = []byte(material[i])
		dataChunks[i] = hex.EncodeToString([]byte(material[i]))
		input[i] = dataChunks[i]
	}
	if len(dataChunks) < len(input) {
		for i := len(dataChunks); i < len(input); i++ {
			input[i] = dataChunks[r.Intn(len(dataChunks))]
		}
	}

	SaveUniqueInput(input[0:])
}

func TestInsertWithSubstring(t *testing.T) {
	input, err := LoadDataMaterial("50000_25000_input")
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=9393")
	if err != nil {
		t.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("DROP INDEX IF EXISTS test_raw_ciphertext_secure_index_idx")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("TRUNCATE TABLE test_raw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("ALTER SEQUENCE test_raw_seq RESTART WITH 1")
	if err != nil {
		t.Fatal(err)
	}



	var dif time.Duration
	for i := 0; i < 3; i++ {
		startTime := time.Now()

		/*
		counter := 0
		for {
			if len(input)-counter == 0 {
				break
			}
			if len(input)-counter < 1000 {
				BulkInsert(t, db, input[counter:])
				break
			}
			BulkInsert(t, db, input[counter:counter+1000])
			counter += 1000
		}*/


		for index := 0; index < len(input); index++ {
			// we use string concatenation to create queries because:
			// 1) using ? with arg will cause database syntax error on (:v1, :v2)
			// 2) if using $ placeholder with arg, db driver will execute query as prepared statement
			// and Acra will not create acrastruct for this field
			_, err := db.Exec(`insert into test_raw(plaintext, ciphertext) values ('\x` + input[index] + `'::bytea, '\x` + input[index] + `'::bytea);`)
			if err != nil {
				t.Fatal(err)
			}
		}

		endTime := time.Now()
		diff := endTime.Sub(startTime)
		dif += diff
		fmt.Printf("INSERT took %v sec\n", diff.Seconds())
	}

	fmt.Printf("INSERT took %v sec in average\n", dif.Seconds() / 3)

}

func TestSelectWithSubstringAcra(t *testing.T) {
	const hashSize = 15
	const selectTimes = 1000
	input, err := LoadDataMaterial("50000_25000_input")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=9393")
	if err != nil {
		t.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("DROP INDEX IF EXISTS test_raw_ciphertext_secure_index_idx")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("TRUNCATE TABLE test_raw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("ALTER SEQUENCE test_raw_seq RESTART WITH 1")
	if err != nil {
		t.Fatal(err)
	}

	counter := 0
	for {
		if len(input)-counter == 0 {
			break
		}
		if len(input)-counter < 1000 {
			BulkInsert(t, db, input[counter:])
			break
		}
		BulkInsert(t, db, input[counter:counter+1000])
		counter += 1000
	}

	//Select0(t, db, selectTimes, "SELECT (0 rows) <with substring>", false, true, hashSize+1)
	//Select1(t, db, selectTimes, "SELECT (1 row) <with substring>", false, true, hashSize+1)
	//Select10(t, db, selectTimes, "SELECT (10 rows) <with substring>", false, true, hashSize + 1)

	_, err = db.Exec("CREATE INDEX IF NOT EXISTS test_raw_ciphertext_secure_index_idx ON test_raw (substr(ciphertext, 1, " + strconv.Itoa(hashSize+1) + "))")
	if err != nil {
		t.Fatal(err)
	}

	db.Close()
	db, err = sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=9393")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		Select0(t, db, selectTimes, "SELECT (0 rows) with B-tree index <with substring>", false, true, hashSize+1)
	}

	db.Close()
	db, err = sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=9393")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		Select1(t, db, selectTimes, "SELECT (1 rows) with B-tree index <with substring>", false, true, hashSize+1)
	}

	db.Close()
	db, err = sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=9393")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		Select10(t, db, selectTimes, "SELECT (10 rows) with B-tree index <with substring>", false, true, hashSize+1)
	}
}

func TestSelectWithSubstringDirectDB(t *testing.T) {
	const selectTimes = 1000

	input, err := LoadDataMaterial("50000_25000_input")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", "sslmode=disable dbname=test user=test password=test host=127.0.0.1 port=5432")
	if err != nil {
		t.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("DROP INDEX IF EXISTS test_raw_ciphertext_secure_index_idx")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("TRUNCATE TABLE test_raw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("ALTER SEQUENCE test_raw_seq RESTART WITH 1")
	if err != nil {
		t.Fatal(err)
	}

	counter := 0
	for {
		if len(input)-counter == 0 {
			break
		}
		if len(input)-counter < 1000 {
			BulkInsert(t, db, input[counter:])
			break
		}
		BulkInsert(t, db, input[counter:counter+1000])
		counter += 1000
	}
	result, err := db.Query("select min(length(plaintext)) from test_raw;")
	if err != nil {
		t.Fatal(err)
	}

	var minSize int
	for result.Next() {
		err = result.Scan(&minSize)
		if err != nil {
			t.Fatal(err)
		}
	}

	//Select0(t, db, selectTimes, "SELECT (0 rows) <with substring>", false, false, minSize)
	//Select1(t, db, selectTimes, "SELECT (1 row) <with substring>", false, false, minSize)
	//Select10(t, db, selectTimes, "SELECT (10 rows) <with substring>", false)

	_, err = db.Exec("CREATE INDEX IF NOT EXISTS test_raw_ciphertext_secure_index_idx ON test_raw (substr(ciphertext, 1, " + strconv.Itoa(minSize) + "))")
	if err != nil {
		t.Fatal(err)
	}

	Select0(t, db, selectTimes, "SELECT (0 rows) with B-tree index <with substring>", false, false, minSize)
	Select1(t, db, selectTimes, "SELECT (1 row) with B-tree index <with substring>", false, false, minSize)
	Select10(t, db, selectTimes, "SELECT (10 rows) with B-tree index <with substring>", false, false, minSize)
}

func Select0(t *testing.T, db *sql.DB, selectTimes int, printPrefix string, separateColumn bool, acra bool, substring int) {
	if acra {
		startTime := time.Now()
		for index := 0; index < selectTimes; index++ {
			// we use string concatenation to create queries because:
			// 1) using ? with arg will cause database syntax error on (:v1, :v2)
			// 2) if using $ placeholder with arg, db driver will execute query as prepared statement
			// and Acra will not create acrastruct for this field
			result, err := db.Query(`SELECT * FROM test_raw WHERE ciphertext='\xffffffffffffffffffffff'`)
			if err != nil {
				t.Fatal(err)
			}

			for result.Next() {
				t.Fatal("bad select (0 rows)")
			}
		}
		endTime := time.Now()
		diff := endTime.Sub(startTime)
		fmt.Printf("%s took %v sec\n", printPrefix, diff.Seconds())
	} else {
		startTime := time.Now()
		for index := 0; index < selectTimes; index++ {
			// we use string concatenation to create queries because:
			// 1) using ? with arg will cause database syntax error on (:v1, :v2)
			// 2) if using $ placeholder with arg, db driver will execute query as prepared statement
			// and Acra will not create acrastruct for this field
			result, err := db.Query(`SELECT * FROM test_raw WHERE substr(ciphertext, 1, ` + strconv.Itoa(substring) + `)='\xffffffffffffffffffffff'`)
			if err != nil {
				t.Fatal(err)
			}

			for result.Next() {
				t.Fatal("bad select (0 rows)")
			}
		}
		endTime := time.Now()
		diff := endTime.Sub(startTime)
		fmt.Printf("%s took %v sec\n", printPrefix, diff.Seconds())
	}

}

func Select1(t *testing.T, db *sql.DB, selectTimes int, printPrefix string, separateColumn bool, acra bool, minSize int) {
	const newEmail = "baLIN152GDOCqwerty1234567890@hotmail.com"
	const expectedRowsFetch = 1

	material := hex.EncodeToString([]byte(newEmail))
	materialBytes := []byte(newEmail)

	_, err := db.Exec(`insert into test_raw(plaintext, ciphertext) values ('\x` + material + `'::bytea, '\x` + material + `'::bytea);`)
	if err != nil {
		t.Fatal(err)
	}

	if separateColumn {
		SelectSeparateColumn(t, db, selectTimes, material, materialBytes, printPrefix, expectedRowsFetch)
	} else {
		SelectWithSubstring(t, db, selectTimes, material, materialBytes, printPrefix, expectedRowsFetch, acra, minSize)
	}
}

func Select10(t *testing.T, db *sql.DB, selectTimes int, printPrefix string, separateColumn bool, acra bool, minSize int) {
	const newEmail = "gspr236entzas.bradley09876543@yahoo.com"
	const expectedRowsFetch = 10

	material := hex.EncodeToString([]byte(newEmail))
	materialBytes := []byte(newEmail)

	for i := 0; i < expectedRowsFetch; i++ {
		_, err := db.Exec(`insert into test_raw(plaintext, ciphertext) values ('\x` + material + `'::bytea, '\x` + material + `'::bytea);`)
		if err != nil {
			t.Fatal(err)
		}
	}
	if separateColumn {
		SelectSeparateColumn(t, db, selectTimes, material, materialBytes, printPrefix, expectedRowsFetch)
	} else {
		SelectWithSubstring(t, db, selectTimes, material, materialBytes, printPrefix, expectedRowsFetch, acra, minSize)
	}
}

func SelectSeparateColumn(t *testing.T, db *sql.DB, selectTimes int, material string, materialBytes []byte, printPrefix string, expectedFetchRows int) {
	var id int
	var fetchedDecryptedCiphertext []byte
	var fetchedPlaintext []byte
	var blindIndex []byte

	startTime := time.Now()
	for index := 0; index < selectTimes; index++ {
		// we use string concatenation to create queries because:
		// 1) using ? with arg will cause database syntax error on (:v1, :v2)
		// 2) if using $ placeholder with arg, db driver will execute query as prepared statement
		// and Acra will not create acrastruct for this field
		result, err := db.Query(`SELECT * FROM test_raw WHERE ciphertext='\x` + material + `'`)
		if err != nil {
			t.Fatal(err)
		}
		counter := 0
		for result.Next() {
			counter++
			err = result.Scan(&id, &fetchedDecryptedCiphertext, &fetchedPlaintext, &blindIndex)
			if err != nil {
				DeleteRedundantRows(t, db, material)
				t.Fatal(err)
			}
			if !bytes.Equal(materialBytes, fetchedDecryptedCiphertext) {
				DeleteRedundantRows(t, db, material)
				t.Fatal("Bad fetch results. Expected decrypted ciphertext: ", material, " Got after AcraServer decryption: ", fetchedDecryptedCiphertext)
			}
		}
		if counter != expectedFetchRows {
			DeleteRedundantRows(t, db, material)
			t.Fatal("bad select result (1 row)")
		}
	}
	endTime := time.Now()
	diff := endTime.Sub(startTime)
	fmt.Printf("%s took %v sec\n", printPrefix, diff.Seconds())

	DeleteRedundantRows(t, db, material)
}

func SelectWithSubstring(t *testing.T, db *sql.DB, selectTimes int, material string, materialBytes []byte, printPrefix string, expectedFetchRows int, acra bool, minSize int) {
	var id int
	var fetchedDecryptedCiphertext []byte
	var fetchedPlaintext []byte

	if acra {
		startTime := time.Now()
		for index := 0; index < selectTimes; index++ {
			// we use string concatenation to create queries because:
			// 1) using ? with arg will cause database syntax error on (:v1, :v2)
			// 2) if using $ placeholder with arg, db driver will execute query as prepared statement
			// and Acra will not create acrastruct for this field
			result, err := db.Query(`SELECT * FROM test_raw WHERE ciphertext='\x` + material + `'`)
			if err != nil {
				t.Fatal(err)
			}

			counter := 0
			for result.Next() {
				counter++
				err = result.Scan(&id, &fetchedDecryptedCiphertext, &fetchedPlaintext)
				if err != nil {
					DeleteRedundantRows(t, db, material)
					t.Fatal(err)
				}
				if !bytes.Equal(materialBytes, fetchedDecryptedCiphertext) {
					DeleteRedundantRows(t, db, material)
					t.Fatal("Bad fetch results. Expected decrypted ciphertext: ", material, " Got after AcraServer decryption: ", hex.EncodeToString(fetchedDecryptedCiphertext))
				}
			}
			if counter != expectedFetchRows {
				DeleteRedundantRows(t, db, material)
				t.Fatal("bad select result (1 row)")
			}
		}
		endTime := time.Now()
		diff := endTime.Sub(startTime)
		fmt.Printf("%s took %v sec\n", printPrefix, diff.Seconds())
	} else {
		startTime := time.Now()
		for index := 0; index < selectTimes; index++ {
			// we use string concatenation to create queries because:
			// 1) using ? with arg will cause database syntax error on (:v1, :v2)
			// 2) if using $ placeholder with arg, db driver will execute query as prepared statement
			// and Acra will not create acrastruct for this field
			result, err := db.Query(`SELECT * FROM test_raw WHERE substr(ciphertext, 1, ` + strconv.Itoa(minSize) + `)='\x` + material[0:minSize*2] + `'`)
			if err != nil {
				t.Fatal(err)
			}

			counter := 0
			for result.Next() {
				counter++
				err = result.Scan(&id, &fetchedDecryptedCiphertext, &fetchedPlaintext)
				if err != nil {
					DeleteRedundantRows(t, db, material)
					t.Fatal(err)
				}
				if !bytes.Equal(materialBytes, fetchedDecryptedCiphertext) {
					DeleteRedundantRows(t, db, material)
					t.Fatal("Bad fetch results. Expected decrypted ciphertext: ", material, " Got after AcraServer decryption: ", hex.EncodeToString(fetchedDecryptedCiphertext))
				}
			}
			if counter != expectedFetchRows {
				DeleteRedundantRows(t, db, material)
				t.Fatal("bad select result (1 row)")
			}
		}
		endTime := time.Now()
		diff := endTime.Sub(startTime)
		fmt.Printf("%s took %v sec\n", printPrefix, diff.Seconds())
	}

	DeleteRedundantRows(t, db, material)
}

func DeleteRedundantRows(t *testing.T, db *sql.DB, material string) {
	_, err := db.Exec(`DELETE FROM test_raw WHERE plaintext='\x` + material + `'`)
	if err != nil {
		t.Fatal(err)
	}
}

func BulkInsert(t *testing.T, db *sql.DB, input []string) {
	index := 0
	query := `insert into test_raw(plaintext, ciphertext) values `
	if len(input) == 1 {
		query += fmt.Sprintf(`('\x%s'::bytea, '\x%s'::bytea);`, input[index], input[index])
	} else {
		for {
			query += fmt.Sprintf(`('\x%s'::bytea, '\x%s'::bytea), `, input[index], input[index])
			index++
			if index == len(input)-1 || index%999 == 0 {
				query += fmt.Sprintf(`('\x%s'::bytea, '\x%s'::bytea);`, input[index], input[index])
				break
			}
		}
	}
	_, err := db.Exec(query)
	if err != nil {
		t.Fatal(err)
	}
}
