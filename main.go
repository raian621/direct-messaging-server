package main

var (
	certfile string = "server.crt"
	keyfile  string = "server.key"
	addr     string = "0.0.0.0"
	port     int    = 8000
)

func main() {
	if err := EnsureTLSFiles(certfile, keyfile); err != nil {
		panic(err)
	}
	StartServer(
		NewServer(addr, port),
		certfile,
		keyfile,
	)
}
