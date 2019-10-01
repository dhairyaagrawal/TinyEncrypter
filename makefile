all: main.c pcg_basic.c encrypt.c decrypt.c
	@echo "Building encryption program"
	@gcc -Wall -Iincludes pcg_basic.c decrypt.c encrypt.c main.c -o program
	@echo "Executable file created. Filename - program"

tests: all test1 test2 test3 test4 test5 test6 test7

test1:
	@echo "Test 1"
	@./program tests/code.py
	@./program tests/code_ciphertext.py tests/code_cipherkey.py
	diff tests/code.py tests/code_ciphertext_recovered.py
	@echo ""

test2:
	@echo "Test 2"
	@./program tests/compressed.zip
	@./program tests/compressed_ciphertext.zip tests/compressed_cipherkey.zip
	diff tests/compressed.zip tests/compressed_ciphertext_recovered.zip
	@echo ""
	
test3:
	@echo "Test 3"
	@./program tests/subtitle.srt
	@./program tests/subtitle_ciphertext.srt tests/subtitle_cipherkey.srt
	diff tests/subtitle.srt tests/subtitle_ciphertext_recovered.srt
	@echo ""
	
test4:
	@echo "Test 4"
	@./program tests/text.txt
	@./program tests/text_ciphertext.txt tests/text_cipherkey.txt
	diff tests/text.txt tests/text_ciphertext_recovered.txt
	@echo ""
	
test5:
	@echo "Test 5"
	@./program tests/picture.jpg
	@./program tests/picture_ciphertext.jpg tests/picture_cipherkey.jpg
	diff tests/picture.jpg tests/picture_ciphertext_recovered.jpg
	@echo ""
	
test6:
	@echo "Test 6 - Zero filesize test"
	@./program tests/zero.txt
	@echo ""
	
test7:
	@echo "Test 7 - Invalid key file test"
	@./program tests/zero.txt tests/zero.txt
	@echo ""
	
clean :
	@rm -f program
	@cd tests/ && rm -f *cipher*
