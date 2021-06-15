pokepacket: main.go layout go.mod
	docker build -t pokepacket .
	docker run pokepacket cat pokepacket > pokepacket
	chmod +x pokepacket

test: pokepacket
	docker run -it -p 9000:9000 pokepacket bash -c '\
		echo -e "services:\n  pokepacket: 9000\nport: 9000\niface: \"eth0\"\nflag: \"9000\"" > config.yaml && \
		./pokepacket'

clean:
	rm -f pokepacket
