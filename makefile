LIB=lib/antlr_generated/strace
LANGUAGE=Python3
LEXER=StraceLexer.g4
PARSER=StraceParser.g4


default: clean antlr


clean:
	find $(LIB) -type f -not -name __init__.py -delete


antlr:
	antlr -Dlanguage=$(LANGUAGE) -o $(LIB) $(LEXER)
	antlr -no-listener -visitor -Dlanguage=$(LANGUAGE) -o $(LIB) $(PARSER)
