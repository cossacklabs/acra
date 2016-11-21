# Usage
## With zones
The same like for correct acra structs:
* add zone like 
```
[acra]$ go build addzone
[acra]$ ./addzone 
{"id":"ZXChVYmCtQgasDlqtrz","public_key":"VUVDMgAAAC3e8NhhAjK+wyOntdyqlPg3c89Vu5z3JskxuxgAQVynNOLnel4c"}
```
* save decoded from base64 public key in file (for example ZXChVYmCtQgasDlqtrz.pub). For example:
```
echo VUVDMgAAAC3e8NhhAjK+wyOntdyqlPg3c89Vu5z3JskxuxgAQVynNOLnel4c | base64 --decode > ZXChVYmCtQgasDlqtrz.pub
```
* create poison record using zone public key
```
go build poisonrecord
[acra]$ ./poisonrecord -acra_public=/path/to/ZXChVYmCtQgasDlqtrz.pub
hSD7VUVDMgAAAC0GPZUAAtxiVBj7+LzTz5+qDQLuIF4MNIPpvuNOoGx5pMFHSmSRICcEJlQAAAAAAQFADAAAABAAAAAgAAAA+HNqMryNiASoXhFJdmkDieAWlfjBN7sOBbj4s96uS0i2PnKT9I9powzVn4CfHzFuCSNJceusSDV14GO1dwAAAAAAAAAAAQFADAAAABAAAABLAAAAofsRDZjjbVuC6pELSJEKLYoKEpYFk6xPQDKQLVFocUgTMM9gVPtKKVkr4AFH2lBTbG3+7+3b9Ebrczl8VLScsF2HDfOFQ2Oo0eUVJ+5d82SSTFmTjJEVOJ+XgXXRyI5bQamIwoYEhA==
```
* Insert into db decoded from base64 this poison record like acrastruct

## Without zones
* create key pair for acra:
```
go build acra_gen_keys
./acra_gen_keys -key_name=test_server
```
* create poison record using this public key
```
[acra]$ ./poisonrecord -acra_public=~/.ssession/test_server.pub
hSD7VUVDMgAAAC373NQJAz5XMsVP3jXLFkFwfBb7H4NjxL6REJbeNZx/7blJodPfICcEJlQAAAAAAQFADAAAABAAAAAgAAAA6YxpknqByuENYMI9rv2U2AMJNTvmqEv+cro8yWTiQ7vGv/B4fy3Ehv0gruPNEdXGsEYNd654+So+ybg6WQAAAAAAAAAAAQFADAAAABAAAAAtAAAA52Ytsk+bGwXy6UxwMvLIyAFhq/3vzOdxZekHkTeRsTK17GAbnOKQBe3U0IHBvbStzVBjYeidNjW4vQxHYXSUzqHlG9kZm/Wp7A==
```

## Optional args
### Poison key
First run of acra or poisonrecord will create `poison_key` - binary file with 32 
byte key that will used like identifier of poison record. As default it's `~/.ssession/poison_key` 
or you can explicitly pass another value for acra like `-poison_key=/path/to/key`
and the same for poisonrecord `-poison_key=/path/to/key`. Key will automatically
generated key if he isn't exists.

### Data length
Optionally you can choose with which data length generate poison record (default 
raw data length 1..100 bytes) with option `-data_length=n`.
This option for case when you have data with specific length and for similarity 
you can explicitly pass this length
```
Usage of ./poisonrecord:
  -acra_public string
    	path to acra public key to use
  -data_length int
    	length of random data for data block in acrastruct. -1 is random in range 1..100 (default -1)
  -poison_key string
    	path to file with poison key (default "~/.ssession/poison_key")
```