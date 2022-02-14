# Collect profiling data

## Start acra-server

```
docker-compose -f benchmarks/docker-compose.pgsql-ssl-server-ssl.yml up
```

## Prepare environment 

```
export OUTPUT_DIR=${OUTPUT_DIR:-/tmp}
export BENCHMARK_NAME=${BENCHMARK_NAME:-default}
export READ_TIMEOUT=${READ_TIMEOUT:-25}
export WRITE_TIMEOUT=${WRITE_TIMEOUT:-25}
```

* `OUTPUT_DIR` - here will be saved profiling data
* `BENCHMARK_NAME` - will be used as suffix name for collected profiling files. Useful to use different filenames with 
  different config files for acra-server
* `READ_TIMEOUT` - amount of time how long collect data from acra-server during `read` command. To collect all data it should 
  be greater than time of script's execution
* `WRITE_TIMEOUT` - amount of time how long collect data from acra-server during `write` command. To collect all data it should
  be greater than time of script's execution

## Setup acra-server's config 

By default, it configured to use filesystem as keystore, with tls connections and client_id extraction.
Use `benchmarks/config/acra-server.yaml` file to change values.

## Setup acra-server's encryptor_config

By default, used to use CryptoEnvelope with acrablocks. You can change it in the file `benchmarks/config/encryptor_config.yaml`

## Run script

```
./benchmarks/run_transparent.sh
```

Output example:
```
run write scripts
run direct write './write.bin 2> >(tee -a default.direct.txt)'
time="2022-02-14T05:36:55+02:00" level=info msg="Took 5.532813209 sec\n"
run acra write './write.bin 2> >(tee -a default.acra.txt)'
time="2022-02-14T05:37:01+02:00" level=info msg="Took 6.512527345 sec\n"
wait 204133
run read scripts without zones
run direct read './read.bin 2> >(tee -a default.direct.txt)'
time="2022-02-14T05:37:29+02:00" level=info msg="Took 3.650667988 sec\n"
run acra read './read.bin 2> >(tee -a default.acra.txt)'
time="2022-02-14T05:37:55+02:00" level=info msg="Took 18.882822578 sec\n"
wait 204252
```

At first, it writes data to database directly and through acra-server.

Second step is read plaintext directly from database and encrypted data through acra-server.
For read command time tracking starts after generation data, before read commands.

Finally, you can find profiling data in `${OUTPUT_DIR}` folder:
```
$ ls output/
default.read.pb.gz  default.write.pb.gz 
```

To view collected data, you need to install pprof:
```
go install github.com/google/pprof@latest
```

Generate and open svg in the browser:
```
go tool pprof -web ${OUTPUT_DIR}/*.pb.gz
```

Generate svg:
```
go tool pprof -svg ${OUTPUT_DIR}/*.pb.gz
```

Look in command-line interactively:
```
go tool pprof ${OUTPUT_DIR}/*.pb.gz
```