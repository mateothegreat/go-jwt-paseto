bench: bench/jwt bench/paseto

bench/paseto:
	go test -bench=. -benchmem .

bench/jwt:
	go test -bench=. -benchmem . ./jwt

test: test/jwt test/paseto

test/paseto:
	go test . -cover

test/jwt:
	go test -v ./jwt -cover