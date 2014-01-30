run () {
    (cd $1 && go test -i && go test -v)
}

run bcrypt
run scrypt
run pbkdf2 
