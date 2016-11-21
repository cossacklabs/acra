package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/utils"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

var DEBUG_PREFIX = []byte("Debug: ")

type NotDebugWriter struct {
	writer io.Writer
}

func NewNotDebugWriter(writer io.Writer) *NotDebugWriter {
	return &NotDebugWriter{writer: writer}
}
func (wr *NotDebugWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, DEBUG_PREFIX) {
		return 0, nil
	}
	return wr.writer.Write(p)

}

func main() {
	db_host := flag.String("db_host", "", "host to db")
	db_port := flag.Int("db_port", 5432, "port to db")

	host := flag.String("host", "0.0.0.0", "host")
	port := flag.Int("port", 9393, "port")
	commands_port := flag.Int("commands_port", 9090, "commands_port")

	keys_dir := flag.String("keys_dir", "~/.ssession", "dir where private app key and public acra key")

	poison_key_path := flag.String("poison_key", poison.DEFAULT_POISON_KEY_PATH, "path to file with poison key")

	hex_format := flag.Bool("hex_bytea", false, "hex format for bytea data (default)")
	escape_format := flag.Bool("escape_bytea", false, "escape format for bytea data")

	server_id := flag.String("server_id", "acra_server", "id that will be sent in secure session")

	verbose := flag.Bool("v", false, "log to stdout")

	debug := flag.Bool("d", false, "debug log")

	stop_on_poison := flag.Bool("s", false, "stop on poison record")
	script_on_poison := flag.String("script", "", "execute script on poison record")

	with_zone := flag.Bool("z", false, "with zone")

	flag.Parse()

	if *debug {
		log.SetOutput(os.Stdout)
	} else if *verbose {
		log.SetOutput(NewNotDebugWriter(os.Stdout))
	} else {
		log.SetOutput(ioutil.Discard)
	}
	if *db_host == "" {
		fmt.Println("Error: you must specify db_host")
		flag.Usage()
		return
	}

	poison_key, err := poison.GetOrCreatePoisonKey(*poison_key_path)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't read poison key", err))
		os.Exit(1)
	}

	config := acra.NewConfig()
	// now it's stub as default values
	config.SetStopOnPoison(*stop_on_poison)
	config.SetScriptOnPoison(*script_on_poison)
	config.SetWithZone(*with_zone)
	config.SetPoisonKey(poison_key)
	config.SetDBHost(*db_host)
	config.SetDBPort(*db_port)
	config.SetProxyHost(*host)
	config.SetProxyPort(*port)
	config.SetProxyCommandsPort(*commands_port)
	config.SetKeysDir(*keys_dir)
	config.SetServerId([]byte(*server_id))
	if *hex_format || !*escape_format {
		config.SetByteaFormat(acra.HEX_BYTEA_FORMAT)
	} else {
		config.SetByteaFormat(acra.ESCAPE_BYTEA_FORMAT)
	}

	server, err := acra.NewServer(config)
	if err != nil {
		panic(err)
	}

	if *debug {
		// start http server for pprof
		go func() {
			err := http.ListenAndServe("127.0.0.1:6060", nil)
			if err != nil {
				log.Printf("Error: %v\n", utils.ErrorMessage("error from debug server", err))
			}
		}()
	}
	if *with_zone {
		go server.StartCommands()
	}
	server.Start()
}
