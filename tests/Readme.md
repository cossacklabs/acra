# Install python requirements
```
pip install -r tests/requirements.txt
```
# Update connection settings
Set next environment variables for test or update test.py:BaseTestCase:
```
TEST_DB_HOST
TEST_DB_PORT
TEST_DB_NAME
TEST_DB_USER
TEST_DB_USER_PASSWORD
```

# Run tests
example
```
TEST_DB_HOST=127.0.0.1 TEST_DB_USER=postgres TEST_DB_USER_PASSWORD=postgres TEST_DB_NAME=acra TEST_DB_PORT=5432  python tests/test.py
``` 
or just
```
python tests/test.py
```