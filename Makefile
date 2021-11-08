build:
	GOOS=windows go build -o wsl2-gpg-agent.exe -ldflags -H=windowsgui main.go
