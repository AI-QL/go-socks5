# Go-Socks5

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

## Feature

The package has the following features:
* "No Auth" mode
* User/Password authentication
* Support for the CONNECT command
* Rules to do granular filtering of commands
* Custom DNS resolution
* Unit tests

## TODO

The package still needs the following:
* Support for the BIND command
* Support for the ASSOCIATE command


## Example

Below is a simple example of usage

```go
// Create a SOCKS5 server
conf := &socks5.Config{}
server, err := socks5.New(conf)
if err != nil {
  panic(err)
}

// Create SOCKS5 proxy on localhost port 8000
if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
  panic(err)
}
```

## Godoc

### Step 1: Install `godoc`
First, ensure that you have `godoc` installed. You can install it using the following command:

```bash
go install golang.org/x/tools/cmd/godoc@latest
```

### Step 2: Run `godoc` Server
Next, run the `godoc` server to serve the documentation for your Go project:

```bash
godoc -http=:6060 -goroot=.
```

This command starts a web server on port 6060, serving the documentation for your Go project.



## Reference

This repository was originally cloned from [go-socks5](https://github.com/armon/go-socks5) due to its long period of inactivity. It is a small yet elegant repo, and we aim to use it as a pilot project to transform it into a comprehensive library with thorough documentation and automation. We will also strive to optimize and enhance it using AI.
