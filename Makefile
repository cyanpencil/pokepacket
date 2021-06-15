pokepacket:
	docker build -t pokepacket .
	docker run pokepacket cat pokepacket > pokepacket
	chmod +x pokepacket

test: pokepacket
	docker run -it -p 9000:9000 -p 9001:9001 pokepacket bash -c '\
		echo "pokepacket: 9000" > services.yaml && \
		./pokepacket eth0'

clean:
	rm -f pokepacket
